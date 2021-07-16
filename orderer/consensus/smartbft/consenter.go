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
	"path"
	"reflect"

	"github.com/golang/protobuf/proto"
	proto2 "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/smartbft"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/multichannel"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/inactive"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

//go:generate mockery -dir . -name InactiveChainRegistry -case underscore -output mocks

// InactiveChainRegistry registers chains that are inactive
type InactiveChainRegistry interface {
	// TrackChain tracks a chain with the given name, and calls the given callback
	// when this chain should be created.
	TrackChain(chainName string, genesisBlock *common.Block, createChain func())
}

// ChainGetter obtains instances of ChainSupport for the given channel
type ChainGetter interface {
	// GetChain obtains the ChainSupport for the given channel.
	// Returns nil, false when the ChainSupport for the given channel
	// isn't found.
	GetChain(chainID string) *multichannel.ChainSupport
}

type PolicyManagerRetriever func(channel string) policies.Manager

// Consenter implementation of the BFT smart based consenter
type Consenter struct {
	CreateChain      func(chainName string)
	icr              InactiveChainRegistry
	GetPolicyManager PolicyManagerRetriever
	Logger           *flogging.FabricLogger
	Cert             []byte
	Comm             *cluster.Comm
	Chains           ChainGetter
	Registrar        *multichannel.Registrar
	WALBaseDir       string
	ClusterDialer    *cluster.PredicateDialer
	Conf             *localconfig.TopLevel
	Metrics          *Metrics
	BCCSP            bccsp.BCCSP
}

// New creates Consenter of type smart bft
func New(
	icr InactiveChainRegistry,
	pmr PolicyManagerRetriever,
	clusterDialer *cluster.PredicateDialer,
	conf *localconfig.TopLevel,
	srvConf comm.ServerConfig,
	srv *comm.GRPCServer,
	r *multichannel.Registrar,
	metricsProvider metrics.Provider,
	bccsp bccsp.BCCSP,
) consensus.Consenter {
	logger := flogging.MustGetLogger("orderer.consensus.smartbft")

	metrics := cluster.NewMetrics(metricsProvider)

	var walConfig WALConfig
	err := mapstructure.Decode(conf.Consensus, &walConfig)
	if err != nil {
		logger.Panicf("Failed to decode consensus configuration: %s", err)
	}

	logger.Infof("XXX WAL Directory is %s", walConfig.WALDir)

	consenter := &Consenter{
		icr:              icr,
		Registrar:        r,
		GetPolicyManager: pmr,
		Conf:             conf,
		ClusterDialer:    clusterDialer,
		Logger:           logger,
		Cert:             srvConf.SecOpts.Certificate,
		Chains:           r,
		WALBaseDir:       walConfig.WALDir,
		Metrics:          NewMetrics(metricsProvider),
		BCCSP:            bccsp,
		CreateChain:      r.CreateChain,
	}

	compareCert := cluster.CachePublicKeyComparisons(func(a, b []byte) bool {
		err := crypto.CertificatesWithSamePublicKey(a, b)
		if err != nil && err != crypto.ErrPubKeyMismatch {
			crypto.LogNonPubKeyMismatchErr(logger.Errorf, err, a, b)
		}
		return err == nil
	})

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
		CompareCertificate: compareCert,
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
	c.Logger.Warningf("Chain %s is of type %v and not etcdraft.Chain", channelID, reflect.TypeOf(cs.Chain))
	return nil
}

func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *common.Metadata) (consensus.Chain, error) {
	m := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), m); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal consensus metadata")
	}
	if m.Options == nil {
		return nil, errors.New("failed to retrieve consensus metadata options")
	}

	selfID, err := c.detectSelfID(m.Consenters)
	if err != nil {
		errNotServiced := fmt.Sprintf("channel %s is not serviced by me", support.ChannelID())
		c.Logger.Errorf(errNotServiced)
		c.icr.TrackChain(support.ChannelID(), support.Block(0), func() {
			c.CreateChain(support.ChannelID())
		})
		return &inactive.Chain{Err: errors.Errorf("channel %s is not serviced by me", support.ChannelID())}, nil
	}
	c.Logger.Infof("Local consenter id is %d", selfID)

	puller, err := newBlockPuller(support, c.ClusterDialer, c.Conf.General.Cluster, c.BCCSP)
	if err != nil {
		c.Logger.Panicf("Failed initializing block puller")
	}

	config, err := configFromMetadataOptions(selfID, m.Options)
	if err != nil {
		return nil, errors.Wrap(err, "failed parsing smartbft configuration")
	}
	c.Logger.Debugf("SmartBFT-Go config: %+v", config)

	configValidator := &ConfigBlockValidator{
		ChannelConfigTemplator: c.Registrar,
		ValidatingChannel:      support.ChannelID(),
		Filters:                c.Registrar,
		ConfigUpdateProposer:   c.Registrar,
		Logger:                 c.Logger,
	}

	chain, err := NewChain(configValidator, selfID, config, path.Join(c.WALBaseDir, support.ChannelID()), puller, c.Comm, c.GetPolicyManager(support.ChannelID()), support, c.Metrics, c.BCCSP)
	if err != nil {
		return nil, errors.Wrap(err, "failed creating a new BFTChain")
	}

	return chain, nil
}

func pemToDER(pemBytes []byte, id uint64, certType string, logger *flogging.FabricLogger) ([]byte, error) {
	bl, _ := pem.Decode(pemBytes)
	if bl == nil {
		logger.Errorf("Rejecting PEM block of %s TLS cert for node %d, offending PEM is: %s", certType, id, string(pemBytes))
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
