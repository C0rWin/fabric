/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package smartbft

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/golang/protobuf/proto"
	proto2 "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/multichannel"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/inactive"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// ChainGetter obtains instances of ChainSupport for the given channel
type ChainGetter interface {
	// GetChain obtains the ChainSupport for the given channel.
	// Returns nil, false when the ChainSupport for the given channel
	// isn't found.
	GetChain(chainID string) *multichannel.ChainSupport
}

// Consenter implementation of the BFT smart based consenter
type Consenter struct {
	Logger           *flogging.FabricLogger
	Cert             []byte
	Comm             *cluster.Comm
	Chains           ChainGetter
	SignerSerializer identity.SignerSerializer
	Registrar        *multichannel.Registrar
}

// New creates Consenter of type smart bft
func New(
	signerSerializer identity.SignerSerializer,
	clusterDialer *cluster.PredicateDialer,
	conf *localconfig.TopLevel,
	srvConf comm.ServerConfig,
	srv *comm.GRPCServer,
	r *multichannel.Registrar,
	metricsProvider metrics.Provider,
) consensus.Consenter {
	logger := flogging.MustGetLogger("orderer.consensus.smartbft")

	metrics := cluster.NewMetrics(metricsProvider)

	consenter := &Consenter{
		Logger:           logger,
		Cert:             srvConf.SecOpts.Certificate,
		Chains:           r,
		SignerSerializer: signerSerializer,
		Registrar:        r,
	}

	consenter.Comm = &cluster.Comm{
		MinimumExpirationWarningInterval: cluster.MinimumExpirationWarningInterval,
		CertExpWarningThreshold:          conf.General.Cluster.CertExpirationWarningThreshold,
		SendBufferSize:                   conf.General.Cluster.SendBufferSize,
		Logger:                           flogging.MustGetLogger("orderer.common.cluster"),
		Chan2Members:                     make(map[string]cluster.MemberMapping),
		Connections:                      cluster.NewConnectionStore(clusterDialer, metrics.EgressTLSConnectionCount),
		Metrics:                          metrics,
		ChanExt:                          consenter,
		H: &Ingreess{
			Logger:        logger,
			ChainSelector: consenter,
		},
	}

	svc := &cluster.Service{
		CertExpWarningThreshold:          conf.General.Cluster.CertExpirationWarningThreshold,
		MinimumExpirationWarningInterval: cluster.MinimumExpirationWarningInterval,
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: metrics,
		},
		StepLogger: flogging.MustGetLogger("orderer.common.cluster.step"),
		Logger:     flogging.MustGetLogger("orderer.common.cluster"),
		Dispatcher: consenter.Comm,
	}

	orderer.RegisterClusterServer(srv.Server(), svc)

	return consenter
}

// ReceiverByChain returns the MessageReceiver for the given channelID or nil
// if not found.
func (c *Consenter) ReceiverByChain(channelID string) MessageReceiver {
	cs := c.Chains.GetChain(channelID)
	if cs == nil {
		return nil
	}
	if cs.Chain == nil {
		c.Logger.Panicf("Programming error - Chain %s is nil although it exists in the mapping", channelID)
	}
	if smartBFTChain, isBFTSmart := cs.Chain.(*BFTChain); isBFTSmart {
		return smartBFTChain
	}
	c.Logger.Warningf("Chain %s is of type %v and not smartbft.Chain", channelID, reflect.TypeOf(cs.Chain))
	return nil
}

func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *common.Metadata) (consensus.Chain, error) {
	m := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), m); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal consensus metadata")
	}

	// TODO: Add options check
	selfID, err := c.detectSelfID(m.Consenters)
	if err != nil {
		// TODO: Add inactive channel tracker
		return &inactive.Chain{Err: errors.Errorf("channel %s is not serviced by me", support.ChainID())}, nil
	}
	c.Logger.Infof("Local consenter id is %d", selfID)

	var nodes []cluster.RemoteNode
	id2Identies := map[uint64][]byte{}
	for _, consenter := range m.Consenters {

		// No need to know yourself
		if selfID == consenter.ConsenterId {
			continue
		}
		serverCertAsDER, err := c.pemToDER(consenter.ServerTlsCert, consenter.ConsenterId, "server")
		if err != nil {
			return nil, errors.WithStack(err)
		}
		clientCertAsDER, err := c.pemToDER(consenter.ClientTlsCert, consenter.ConsenterId, "client")
		if err != nil {
			return nil, errors.WithStack(err)
		}

		nodes = append(nodes, cluster.RemoteNode{
			ID:            consenter.ConsenterId,
			ClientTLSCert: clientCertAsDER,
			ServerTLSCert: serverCertAsDER,
			Endpoint:      fmt.Sprintf("%s:%d", consenter.Host, consenter.Port),
		})
		id2Identies[consenter.ConsenterId] = consenter.Identity
	}

	// build configuration bundle to get policy manager
	block, err := lastConfigBlockFromLedger(support)
	if err != nil {
		return nil, errors.Errorf("failed to obtain last config block cause of: %s", err)
	}
	if block == nil {
		return nil, errors.New("nil block")
	}
	envelopeConfig, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return nil, err
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelopeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting bundle from envelope")
	}

	return NewChain(selfID,
		nil, // TODO: Initialize blocks puller
		c.Comm,
		c.SignerSerializer,
		bundle.PolicyManager(),
		nodes,
		id2Identies,
		support,
	), nil
}

func (c *Consenter) pemToDER(pemBytes []byte, id uint64, certType string) ([]byte, error) {
	bl, _ := pem.Decode(pemBytes)
	if bl == nil {
		c.Logger.Errorf("Rejecting PEM block of %s TLS cert for node %d, offending PEM is: %s", certType, id, string(pemBytes))
		return nil, errors.Errorf("invalid PEM block")
	}
	return bl.Bytes, nil
}

func (c *Consenter) detectSelfID(consenters []*smartbft.Consenter) (uint64, error) {
	var serverCertificates []string
	for _, cst := range consenters {
		serverCertificates = append(serverCertificates, string(cst.ServerTlsCert))
		if bytes.Equal(c.Cert, cst.ServerTlsCert) {
			return cst.ConsenterId, nil
		}
	}

	c.Logger.Warning("Could not find", string(c.Cert), "among", serverCertificates)
	return 0, cluster.ErrNotInChannel
}

// TargetChannel extracts the channel from the given proto.Message.
// Returns an empty string on failure.
func (c *Consenter) TargetChannel(message proto2.Message) string {
	switch req := message.(type) {
	case *orderer.ConsensusRequest:
		return req.Channel
	case *orderer.SubmitRequest:
		return req.Channel
	default:
		return ""
	}
}
