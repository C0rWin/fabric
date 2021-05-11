/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sort"
	"time"

	types2 "github.com/hyperledger/fabric/orderer/consensus/smartbft/types"

	cs "github.com/SmartBFT-Go/randomcommittees"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	utils2 "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// newBlockPuller creates a new block puller
func newBlockPuller(
	committeeDisabled bool,
	support consensus.ConsenterSupport,
	baseDialer *cluster.PredicateDialer,
	clusterConfig localconfig.Cluster) (BlockPuller, error) {

	verifyBlockSequence := func(blocks []*common.Block, _ string) error {
		return cluster.VerifyBlocksBFT(blocks, support)
	}

	stdDialer := &cluster.StandardDialer{
		ClientConfig: baseDialer.ClientConfig.Clone(),
	}
	stdDialer.ClientConfig.AsyncConnect = false
	stdDialer.ClientConfig.SecOpts.VerifyCertificate = nil

	cr := &CommitteeRetriever{
		committeeDisabled:     committeeDisabled,
		NewCommitteeSelection: cs.NewCommitteeSelection,
		Logger:                flogging.MustGetLogger("orderer.consensus.smartbft.committee"),
		Ledger:                support,
	}

	logger := flogging.MustGetLogger("orderer.common.cluster.puller")

	currentCommittee, err := cr.CurrentCommittee()
	if err != nil {
		return nil, err
	}

	committeeIdentifiers := currentCommittee.IDs()

	logger.Debugf("Current committee: %v", committeeIdentifiers)

	committeeIDs := make(map[uint64]struct{})
	for _, id := range committeeIdentifiers {
		committeeIDs[uint64(id)] = struct{}{}
	}

	consensusMD := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), consensusMD); err != nil {
		return nil, err
	}

	endpointsInCommittee := make(map[string]struct{})
	for _, consenter := range consensusMD.Consenters {
		if _, exists := committeeIDs[consenter.ConsenterId]; !exists {
			logger.Debugf("%d %s is not in the committee", consenter.ConsenterId, consenter.Host)
			continue
		}
		endpointsInCommittee[consenter.Host] = struct{}{}
	}

	// Extract the TLS CA certs and endpoints from the configuration,
	endpoints, err := etcdraft.EndpointconfigFromFromSupport(support)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Endpoints in committee: %v", endpointsInCommittee)

	if len(endpointsInCommittee) > 0 {
		var filteredEndpoints []cluster.EndpointCriteria
		var filteredEndpointsURIs []string
		for _, ep := range endpoints {
			host, _, err := net.SplitHostPort(ep.Endpoint)
			if err != nil {
				logger.Warnf("Invalid host port string %s: %v", ep.Endpoint, err)
				continue
			}
			if _, exists := endpointsInCommittee[host]; !exists {
				continue
			}
			filteredEndpoints = append(filteredEndpoints, ep)
			filteredEndpointsURIs = append(filteredEndpointsURIs, ep.Endpoint)
		}
		endpoints = filteredEndpoints
		logger.Debugf("Filtering out endpoints of nodes not in the committee, remaining endpoints: %v", filteredEndpointsURIs)
	} else {
		logger.Debugf("Endpoints and consenter endpoints are disjoint, using the endpoints without filtering by committee")
	}

	der, _ := pem.Decode(stdDialer.ClientConfig.SecOpts.Certificate)
	if der == nil {
		return nil, errors.Errorf("client certificate isn't in PEM format: %v",
			string(stdDialer.ClientConfig.SecOpts.Certificate))
	}

	bp := &cluster.BlockPuller{
		VerifyBlockSequence: verifyBlockSequence,
		Logger:              logger,
		RetryTimeout:        clusterConfig.ReplicationRetryTimeout,
		MaxTotalBufferBytes: clusterConfig.ReplicationBufferSize,
		FetchTimeout:        clusterConfig.ReplicationPullTimeout,
		Endpoints:           endpoints,
		Signer:              support,
		TLSCert:             der.Bytes,
		Channel:             support.ChainID(),
		Dialer:              stdDialer,
	}

	return bp, nil
}

func getViewMetadataFromBlock(block *common.Block) (smartbftprotos.ViewMetadata, error) {
	if block.Header.Number == 0 {
		// Genesis block has no prior metadata so we just return an un-initialized metadata
		return smartbftprotos.ViewMetadata{}, nil
	}

	signatureMetadata := utils2.GetMetadataFromBlockOrPanic(block, common.BlockMetadataIndex_SIGNATURES)
	ordererMD := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMD); err != nil {
		return smartbftprotos.ViewMetadata{}, errors.Wrap(err, "failed unmarshaling OrdererBlockMetadata")
	}

	var viewMetadata smartbftprotos.ViewMetadata
	if err := proto.Unmarshal(ordererMD.ConsenterMetadata, &viewMetadata); err != nil {
		return smartbftprotos.ViewMetadata{}, err
	}

	return viewMetadata, nil
}

func configFromMetadataOptions(selfID uint64, options *smartbft.Options) (types.Configuration, error) {
	var err error

	config := types.DefaultConfig
	config.SelfID = selfID

	if options == nil {
		return config, errors.New("config metadata options field is nil")
	}

	config.RequestBatchMaxCount = options.RequestBatchMaxCount
	config.RequestBatchMaxBytes = options.RequestBatchMaxBytes
	if config.RequestBatchMaxInterval, err = time.ParseDuration(options.RequestBatchMaxInterval); err != nil {
		return config, errors.Wrap(err, "bad config metadata option RequestBatchMaxInterval")
	}
	config.IncomingMessageBufferSize = options.IncomingMessageBufferSize
	config.RequestPoolSize = options.RequestPoolSize
	if config.RequestForwardTimeout, err = time.ParseDuration(options.RequestForwardTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option RequestForwardTimeout")
	}
	if config.RequestComplainTimeout, err = time.ParseDuration(options.RequestComplainTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option RequestComplainTimeout")
	}
	if config.RequestAutoRemoveTimeout, err = time.ParseDuration(options.RequestAutoRemoveTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option RequestAutoRemoveTimeout")
	}
	if config.ViewChangeResendInterval, err = time.ParseDuration(options.ViewChangeResendInterval); err != nil {
		return config, errors.Wrap(err, "bad config metadata option ViewChangeResendInterval")
	}
	if config.ViewChangeTimeout, err = time.ParseDuration(options.ViewChangeTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option ViewChangeTimeout")
	}
	if config.LeaderHeartbeatTimeout, err = time.ParseDuration(options.LeaderHeartbeatTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option LeaderHeartbeatTimeout")
	}
	config.LeaderHeartbeatCount = options.LeaderHeartbeatCount
	if config.CollectTimeout, err = time.ParseDuration(options.CollectTimeout); err != nil {
		return config, errors.Wrap(err, "bad config metadata option CollectTimeout")
	}
	config.SyncOnStart = options.SyncOnStart
	config.SpeedUpViewChange = options.SpeedUpViewChange

	if options.DecisionsPerLeader == 0 {
		config.DecisionsPerLeader = 1
	}

	// Enable rotation by default, but optionally disable it
	switch options.LeaderRotation {
	case smartbft.Options_OFF:
		config.LeaderRotation = false
		config.DecisionsPerLeader = 0
	default:
		config.LeaderRotation = true
	}

	if err = config.Validate(); err != nil {
		return config, errors.Wrap(err, "config validation failed")
	}

	return config, nil
}

// RequestInspector inspects incomming requests and validates serialized identity
type RequestInspector struct {
	ValidateIdentityStructure func(identity *msp.SerializedIdentity) error
}

func (ri *RequestInspector) RequestID(rawReq []byte) types.RequestInfo {
	req, err := ri.unwrapReq(rawReq)
	if err != nil {
		return types.RequestInfo{}
	}
	reqInfo, err := ri.requestIDFromSigHeader(req.sigHdr)
	if err != nil {
		return types.RequestInfo{}
	}
	return reqInfo
}

type request struct {
	sigHdr   *common.SignatureHeader
	envelope *common.Envelope
	chHdr    *common.ChannelHeader
}

func (ri *RequestInspector) requestIDFromSigHeader(sigHdr *common.SignatureHeader) (types.RequestInfo, error) {
	sID := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(sigHdr.Creator, sID); err != nil {
		return types.RequestInfo{}, errors.Wrap(err, "identity isn't an MSP Identity")
	}

	if err := ri.ValidateIdentityStructure(sID); err != nil {
		return types.RequestInfo{}, err
	}

	var preimage []byte
	preimage = append(preimage, sigHdr.Nonce...)
	preimage = append(preimage, sigHdr.Creator...)
	txID := sha256.Sum256(preimage)
	clientID := sha256.Sum256(sigHdr.Creator)
	return types.RequestInfo{
		ID:       hex.EncodeToString(txID[:]),
		ClientID: hex.EncodeToString(clientID[:]),
	}, nil
}

func (ri *RequestInspector) unwrapReq(req []byte) (*request, error) {
	envelope, err := utils2.UnmarshalEnvelope(req)
	if err != nil {
		return nil, err
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling payload")
	}

	if payload.Header == nil {
		return nil, errors.Errorf("no header in payload")
	}

	sigHdr := &common.SignatureHeader{}
	if err := proto.Unmarshal(payload.Header.SignatureHeader, sigHdr); err != nil {
		return nil, err
	}

	if len(payload.Header.ChannelHeader) == 0 {
		return nil, errors.New("no channel header in payload")
	}

	chdr, err := utils2.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, errors.WithMessage(err, "error unmarshaling channel header")
	}

	return &request{
		chHdr:    chdr,
		sigHdr:   sigHdr,
		envelope: envelope,
	}, nil
}

// ConfigurationEnvelop extract configuration envelop
func ConfigurationEnvelop(configBlock *common.Block) (*common.ConfigEnvelope, error) {
	envelopeConfig, err := utils2.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract envelop from block")
	}

	payload, err := utils2.UnmarshalPayload(envelopeConfig.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal envelop payload")
	}

	configEnvelope, err := configtx.UnmarshalConfigEnvelope(payload.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal configuration payload")
	}
	return configEnvelope, nil
}

// ConsenterCertificate denotes a TLS certificate of a consenter
type ConsenterCertificate []byte

// IsConsenterOfChannel returns whether the caller is a consenter of a channel
// by inspecting the given configuration block.
// It returns nil if true, else returns an error.
func (conCert ConsenterCertificate) IsConsenterOfChannel(configBlock *common.Block) error {
	if configBlock == nil {
		return errors.New("nil block")
	}
	envelopeConfig, err := utils2.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return err
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelopeConfig)
	if err != nil {
		return err
	}
	oc, exists := bundle.OrdererConfig()
	if !exists {
		return errors.New("no orderer config in bundle")
	}
	if oc.ConsensusType() != "smartbft" {
		return errors.New("not a SmartBFT config block")
	}
	m := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(oc.ConsensusMetadata(), m); err != nil {
		return err
	}

	for _, consenter := range m.Consenters {
		fmt.Println(base64.StdEncoding.EncodeToString(consenter.ServerTlsCert))
		if bytes.Equal(conCert, consenter.ServerTlsCert) || bytes.Equal(conCert, consenter.ClientTlsCert) {
			return nil
		}
	}
	return cluster.ErrNotInChannel
}

func RemoteNodesFromConfigBlock(block *common.Block, selfID uint64, logger *flogging.FabricLogger) (*nodeConfig, error) {
	logger.Debugf("Computing nodes from block %d", block.Header.Number)
	env := &common.Envelope{}
	if err := proto.Unmarshal(block.Data.Data[0], env); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling envelope of config block")
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(env)
	if err != nil {
		return nil, errors.Wrap(err, "failed getting a new bundle from envelope of config block")
	}

	oc, ok := bundle.OrdererConfig()
	if !ok {
		return nil, errors.New("no orderer config in config block")
	}

	m := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(oc.ConsensusMetadata(), m); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal consensus metadata")
	}
	if m.Options == nil {
		return nil, errors.New("failed to retrieve consensus metadata options")
	}

	var nodeIDs []uint64
	var remoteNodes []cluster.RemoteNode
	id2SelectionPKs := map[uint64][]byte{}
	id2Identities := map[uint64][]byte{}
	for _, consenter := range m.Consenters {
		sanitizedID, err := crypto.SanitizeIdentity(consenter.Identity)
		if err != nil {
			logger.Panicf("Failed to sanitize identity: %v", err)
		}
		id2Identities[consenter.ConsenterId] = sanitizedID

		if len(consenter.SelectionPk) > 0 {
			pkStr := string(consenter.SelectionPk)
			pubKey, err := base64.StdEncoding.DecodeString(pkStr)
			if err != nil {
				logger.Warnf("Node %d's public key %s is not a base64 encoded string: %v", consenter.ConsenterId, pkStr, err)
				continue
			}
			id2SelectionPKs[consenter.ConsenterId] = pubKey
		} else {
			logger.Warnf("Node %d lacks a committee public key", consenter.ConsenterId)
		}

		nodeIDs = append(nodeIDs, consenter.ConsenterId)

		// No need to know yourself
		if selfID == consenter.ConsenterId {
			continue
		}
		serverCertAsDER, err := pemToDER(consenter.ServerTlsCert, consenter.ConsenterId, "server", logger)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		clientCertAsDER, err := pemToDER(consenter.ClientTlsCert, consenter.ConsenterId, "client", logger)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		// Validate certificate structure
		for _, cert := range [][]byte{serverCertAsDER, clientCertAsDER} {
			if _, err := x509.ParseCertificate(cert); err != nil {
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
				logger.Errorf("Invalid certificate: %s", string(pemBytes))
				return nil, err
			}
		}

		remoteNodes = append(remoteNodes, cluster.RemoteNode{
			ID:            consenter.ConsenterId,
			ClientTLSCert: clientCertAsDER,
			ServerTLSCert: serverCertAsDER,
			Endpoint:      fmt.Sprintf("%s:%d", consenter.Host, consenter.Port),
		})
	}

	sort.Slice(nodeIDs, func(i, j int) bool {
		return nodeIDs[i] < nodeIDs[j]
	})

	return &nodeConfig{
		id2SectionPK:  id2SelectionPKs,
		remoteNodes:   remoteNodes,
		id2Identities: id2Identities,
		nodeIDs:       nodeIDs,
	}, nil

}

type nodeConfig struct {
	id2SectionPK  NodeIdentitiesByID
	id2Identities NodeIdentitiesByID
	remoteNodes   []cluster.RemoteNode
	nodeIDs       []uint64
}

func (nc *nodeConfig) Nodes(logger Logger) committee.Nodes {
	var nodes committee.Nodes
	for _, n := range nc.nodeIDs {
		if pk, exists := nc.id2SectionPK[n]; !exists {
			logger.Warnf("Node %d doesn't have a public key", n)
			continue
		} else {
			nodes = append(nodes, committee.Node{
				ID:     int32(n),
				PubKey: pk,
			})
		}
	}

	return nodes
}

func (nc *nodeConfig) NodesNoPubKeys(logger Logger) committee.Nodes {
	var nodes committee.Nodes
	for _, n := range nc.nodeIDs {
		pk := nc.id2SectionPK[n]
		nodes = append(nodes, committee.Node{
			ID:     int32(n),
			PubKey: pk,
		})
	}

	return nodes
}

// RuntimeConfig defines the configuration of the consensus
// that is related to runtime.
type RuntimeConfig struct {
	BFTConfig                types.Configuration
	isConfig                 bool
	logger                   *flogging.FabricLogger
	id                       uint64
	LastCommittedBlockHash   string
	RemoteNodes              []cluster.RemoteNode
	ID2Identities            NodeIdentitiesByID
	LastBlock                *common.Block
	LastConfigBlock          *common.Block
	Nodes                    []uint64
	CommitteeMetadata        *types2.CommitteeMetadata
	OnCommitteeChange        func(prevCommittee []int32, allNodes []uint64)
	committeeMinimumLifespan uint32
	changesCommittee         bool
}

func (rtc RuntimeConfig) BlockCommitted(block *common.Block) (RuntimeConfig, error) {
	if _, err := cluster.ConfigFromBlock(block); err == nil {
		return rtc.configBlockCommitted(block)
	}
	cm, err := types2.CommitteeMetadataFromBlock(block)
	if err != nil {
		return RuntimeConfig{}, err
	}

	changesCommittee := cm != nil && cm.CommitteeShiftAt == int64(block.Header.Number)
	if changesCommittee {
		rtc.OnCommitteeChange(cm.CommitteeAtShift.IDs(), rtc.Nodes)
	}

	return RuntimeConfig{
		changesCommittee:         changesCommittee,
		OnCommitteeChange:        rtc.OnCommitteeChange,
		CommitteeMetadata:        cm,
		BFTConfig:                rtc.BFTConfig,
		id:                       rtc.id,
		logger:                   rtc.logger,
		LastCommittedBlockHash:   hex.EncodeToString(block.Header.Hash()),
		Nodes:                    rtc.Nodes,
		ID2Identities:            rtc.ID2Identities,
		RemoteNodes:              rtc.RemoteNodes,
		LastBlock:                block,
		LastConfigBlock:          rtc.LastConfigBlock,
		committeeMinimumLifespan: rtc.committeeMinimumLifespan,
	}, nil
}

func (rtc RuntimeConfig) configBlockCommitted(block *common.Block) (RuntimeConfig, error) {
	nodeConf, err := RemoteNodesFromConfigBlock(block, rtc.id, rtc.logger)
	if err != nil {
		return rtc, errors.Wrap(err, "remote nodes cannot be computed, rejecting config block")
	}

	committeeConfig, bftConfig, err := configBlockToBFTConfig(rtc.id, block)
	if err != nil {
		return RuntimeConfig{}, err
	}

	if committeeConfig == nil {
		committeeConfig = defaultCommitteeConfig
		rtc.logger.Infof("Committee config is not defined, using the default committee config %v", committeeConfig)
	}

	cm, err := types2.CommitteeMetadataFromBlock(block)
	if err != nil {
		return RuntimeConfig{}, err
	}

	changesCommittee := cm != nil && cm.CommitteeShiftAt == int64(block.Header.Number)
	if changesCommittee {
		rtc.OnCommitteeChange(cm.CommitteeAtShift.IDs(), rtc.Nodes)
	}

	return RuntimeConfig{
		changesCommittee:         changesCommittee,
		OnCommitteeChange:        rtc.OnCommitteeChange,
		CommitteeMetadata:        cm,
		BFTConfig:                bftConfig,
		isConfig:                 true,
		id:                       rtc.id,
		logger:                   rtc.logger,
		LastCommittedBlockHash:   hex.EncodeToString(block.Header.Hash()),
		Nodes:                    nodeConf.nodeIDs,
		ID2Identities:            nodeConf.id2Identities,
		RemoteNodes:              nodeConf.remoteNodes,
		LastBlock:                block,
		LastConfigBlock:          block,
		committeeMinimumLifespan: committeeConfig.CommitteeMinimumLifespan,
	}, nil
}

func parseCommitteeConfig(nodeConf *nodeConfig, committeeConfig *smartbft.CommitteeConfig, logger Logger) committee.Config {
	var nodes committee.Nodes
	for _, n := range nodeConf.nodeIDs {
		if pk, exists := nodeConf.id2SectionPK[n]; !exists {
			logger.Warnf("Node %d doesn't have a public key", n)
			nodes = nil
			break
		} else {
			nodes = append(nodes, committee.Node{
				ID:     int32(n),
				PubKey: pk,
			})
		}
	}

	if committeeConfig.Disabled && len(nodes) > 0 {
		logger.Warnf("Committee nodes are configured, but committee selection is disabled")
		nodes = nil
	}

	var weights []committee.Weight
	for _, w := range committeeConfig.Weights {
		if _, exists := nodeConf.id2SectionPK[uint64(w.Id)]; !exists {
			logger.Warnf("Node %d has a weight but doesn't have a public key or is not a consenter", w.Id)
			nodes = nil
			break
		}
		weights = append(weights, committee.Weight{
			ID:     w.Id,
			Weight: int32(w.Weight),
		})
	}

	var mandatoryNodes []int32
	for _, n := range committeeConfig.MandatoryNodes {

		if _, exists := nodeConf.id2SectionPK[uint64(n)]; !exists {
			logger.Warnf("Node %d appears as a mandatory node but doesn't have a public key or is not a consenter", n)
			nodes = nil
			break
		}

		mandatoryNodes = append(mandatoryNodes, n)
	}

	return committee.Config{
		InverseFailureChance:       int64(committeeConfig.InverseFailureChance),
		FailedTotalNodesPercentage: int64(committeeConfig.FailedTotalNodesPercentage),
		MinimumLifespan:            int32(committeeConfig.CommitteeMinimumLifespan),
		Weights:                    weights,
		MandatoryNodes:             mandatoryNodes,
		Nodes:                      nodes,
	}
}

func consensusMDFromBlock(block *common.Block) (*smartbft.ConfigMetadata, error) {
	if block == nil || block.Data == nil || len(block.Data.Data) == 0 {
		return nil, errors.New("empty block")
	}

	env, err := utils2.UnmarshalEnvelope(block.Data.Data[0])
	if err != nil {
		return nil, err
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(env)
	if err != nil {
		return nil, err
	}

	oc, ok := bundle.OrdererConfig()
	if !ok {
		return nil, errors.New("no orderer config")
	}

	consensusMD := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(oc.ConsensusMetadata(), consensusMD); err != nil {
		return nil, err
	}

	if consensusMD.Options != nil {
		if consensusMD.Options.CommitteeConfig == nil {
			consensusMD.Options.CommitteeConfig = defaultCommitteeConfig
		}
	}

	return consensusMD, nil
}

func configBlockToBFTConfig(selfID uint64, block *common.Block) (*smartbft.CommitteeConfig, types.Configuration, error) {
	consensusMD, err := consensusMDFromBlock(block)
	if err != nil {
		return nil, types.Configuration{}, err
	}
	consensusConfig, err := configFromMetadataOptions(selfID, consensusMD.Options)
	return consensusMD.Options.CommitteeConfig, consensusConfig, err
}

func isConfigBlock(block *common.Block) bool {
	if block.Data == nil || len(block.Data.Data) != 1 {
		return false
	}
	env, err := utils2.UnmarshalEnvelope(block.Data.Data[0])
	if err != nil {
		return false
	}
	payload, err := utils2.GetPayload(env)
	if err != nil {
		return false
	}

	if payload.Header == nil {
		return false
	}

	hdr, err := utils2.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return false
	}
	return common.HeaderType(hdr.Type) == common.HeaderType_CONFIG
}

type PRG struct {
	expandBuff func(ctr uint64) []byte
	ctr        uint64
	buffer     []byte
}

func NewPRG(seed []byte) *PRG {
	// Expansion function is:
	// HMAC(seed, SHA256(ctr))
	expand := func(ctr uint64) []byte {
		buff := make([]byte, 8)
		binary.BigEndian.PutUint64(buff, ctr)

		h := sha256.New()
		h.Write(buff)
		ctrHash := h.Sum(nil)

		prf := hmac.New(sha256.New, seed)
		prf.Write(ctrHash)
		return prf.Sum(nil)
	}

	return &PRG{
		expandBuff: expand,
	}
}

func (r *PRG) Read(p []byte) (n int, err error) {
	for len(r.buffer) < len(p) {
		r.ctr++
		r.buffer = append(r.buffer, r.expandBuff(r.ctr)...)
	}

	n = copy(p, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}

var (
	defaultCommitteeConfig = &smartbft.CommitteeConfig{
		FailedTotalNodesPercentage: 20,
		InverseFailureChance:       1000000,
		CommitteeMinimumLifespan:   1,
	}
)

func ProposalToBlock(proposal types.Proposal) (*common.Block, error) {
	// initialize block with empty fields
	block := &common.Block{
		Data:     &common.BlockData{},
		Metadata: &common.BlockMetadata{},
	}

	if len(proposal.Header) == 0 {
		return nil, errors.New("proposal header cannot be nil")
	}

	hdr := &asn1Header{}

	if _, err := asn1.Unmarshal(proposal.Header, hdr); err != nil {
		return nil, errors.Wrap(err, "bad header")
	}

	block.Header = &common.BlockHeader{
		Number:       hdr.Number.Uint64(),
		PreviousHash: hdr.PreviousHash,
		DataHash:     hdr.DataHash,
	}

	if len(proposal.Payload) == 0 {
		return nil, errors.New("proposal payload cannot be nil")
	}

	tuple := &ByteBufferTuple{}
	if err := tuple.FromBytes(proposal.Payload); err != nil {
		return nil, errors.Wrap(err, "bad payload and metadata tuple")
	}

	if err := proto.Unmarshal(tuple.A, block.Data); err != nil {
		return nil, errors.Wrap(err, "bad payload")
	}

	if err := proto.Unmarshal(tuple.B, block.Metadata); err != nil {
		return nil, errors.Wrap(err, "bad metadata")
	}
	return block, nil
}

type asn1Header struct {
	Number       *big.Int
	PreviousHash []byte
	DataHash     []byte
}

// removeDuplicates takes a list and returns a list with the same values but without duplicates
func removeDuplicates(list []int32) []int32 {
	keys := make(map[int32]bool)
	var noDupsList []int32
	for _, entry := range list {
		if _, val := keys[entry]; !val {
			keys[entry] = true
			noDupsList = append(noDupsList, entry)
		}
	}
	return noDupsList
}

// agreedSuspects gets a list of all suspects (a concatenation of all suspects lists)
// it returns the suspects that appear at least f+1 times in the given list (sorted)
func agreedSuspects(allSuspects []int32, f int32) []int32 {
	votes := make(map[int32]int32)

	for _, s := range allSuspects {
		votes[s]++
	}

	var agreedSuspects []int32
	for s, v := range votes {
		if v >= f+1 {
			agreedSuspects = append(agreedSuspects, s)
		}
	}

	sort.Slice(agreedSuspects, func(i, j int) bool { return agreedSuspects[i] < agreedSuspects[j] })

	return agreedSuspects
}
