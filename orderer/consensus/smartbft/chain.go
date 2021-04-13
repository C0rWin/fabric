/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	cs "github.com/SmartBFT-Go/randomcommittees"

	"github.com/hyperledger/fabric/protos/orderer"

	smartbft "github.com/SmartBFT-Go/consensus/pkg/consensus"
	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/pkg/wal"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/msgprocessor"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	smartbft2 "github.com/hyperledger/fabric/protos/orderer/smartbft"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// BlockPuller is used to pull blocks from other OSN
type BlockPuller interface {
	PullBlock(seq uint64) *common.Block
	HeightsByEndpoints() (map[string]uint64, error)
	Close()
}

// WALConfig consensus specific configuration parameters from orderer.yaml; for SmartBFT only WALDir is relevant.
type WALConfig struct {
	WALDir            string // WAL data of <my-channel> is stored in WALDir/<my-channel>
	SnapDir           string // Snapshots of <my-channel> are stored in SnapDir/<my-channel>
	EvictionSuspicion string // Duration threshold that the node samples in order to suspect its eviction from the channel.
}

type ConfigValidator interface {
	ValidateConfig(env *common.Envelope) error
}

type signerSerializer interface {
	// Sign a message and return the signature over the digest, or error on failure
	Sign(message []byte) ([]byte, error)

	// Serialize converts an identity to bytes
	Serialize() ([]byte, error)
}

// BFTChain implements Chain interface to wire with
// BFT smart library
type BFTChain struct {
	cs               committee.Selection
	RuntimeConfig    *atomic.Value
	Channel          string
	Config           types.Configuration
	BlockPuller      BlockPuller
	Comm             cluster.Communicator
	SignerSerializer signerSerializer
	PolicyManager    policies.Manager
	Logger           *flogging.FabricLogger
	WALDir           string
	consensus        *smartbft.Consensus
	support          consensus.ConsenterSupport
	verifier         *Verifier
	assembler        *Assembler
	Metrics          *Metrics
	heartbeatMonitor *HeartbeatMonitor
}

// NewChain creates new BFT Smart chain
func NewChain(
	privateKeyBytesHash []byte,
	cv ConfigValidator,
	selfID uint64,
	config types.Configuration,
	walDir string,
	blockPuller BlockPuller,
	comm cluster.Communicator,
	signerSerializer signerSerializer,
	policyManager policies.Manager,
	support consensus.ConsenterSupport,
	metrics *Metrics,
) (*BFTChain, error) {

	requestInspector := &RequestInspector{
		ValidateIdentityStructure: func(_ *msp.SerializedIdentity) error {
			return nil
		},
	}

	logger := flogging.MustGetLogger("orderer.consensus.smartbft.chain").With(zap.String("channel", support.ChainID()))

	committeeSelection := cs.NewCommitteeSelection(logger)
	rndSeed := NewPRG(privateKeyBytesHash)
	publicKey, privateKey, err := committeeSelection.GenerateKeyPair(rndSeed)
	if err != nil {
		return nil, errors.Wrap(err, "failed generating committee selection key pair")
	}

	c := &BFTChain{
		cs:               committeeSelection,
		RuntimeConfig:    &atomic.Value{},
		Channel:          support.ChainID(),
		Config:           config,
		WALDir:           walDir,
		Comm:             comm,
		support:          support,
		SignerSerializer: signerSerializer,
		PolicyManager:    policyManager,
		BlockPuller:      blockPuller,
		Logger:           logger,
		Metrics: &Metrics{
			ClusterSize:          metrics.ClusterSize.With("channel", support.ChainID()),
			CommittedBlockNumber: metrics.CommittedBlockNumber.With("channel", support.ChainID()),
			IsLeader:             metrics.IsLeader.With("channel", support.ChainID()),
			LeaderID:             metrics.LeaderID.With("channel", support.ChainID()),
		},
	}

	lastBlock := LastBlockFromLedgerOrPanic(support, c.Logger)
	lastConfigBlock := LastConfigBlockFromLedgerOrPanic(support, c.Logger)

	rtc := RuntimeConfig{
		logger: logger,
		id:     selfID,
	}
	rtc, err = rtc.BlockCommitted(lastConfigBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed constructing RuntimeConfig")
	}
	rtc, err = rtc.BlockCommitted(lastBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed constructing RuntimeConfig")
	}

	c.RuntimeConfig.Store(rtc)

	if len(rtc.CommitteeConfig.Nodes) > 0 {
		err = committeeSelection.Initialize(int32(selfID), privateKey, rtc.CommitteeConfig.Nodes)
		if err != nil {
			return nil, errors.Wrap(err, "failed initializing committee selection instance")
		}
	}

	logger.Infof("Initialized committee selection with for %d with public key %s", selfID, base64.StdEncoding.EncodeToString(publicKey))
	logger.Infof("Nodes: %v", rtc.CommitteeConfig.Nodes)

	c.verifier = buildVerifier(cv, c.RuntimeConfig, support, requestInspector, policyManager)
	c.consensus = bftSmartConsensusBuild(c, requestInspector)

	// TODO setup heartbeat monitor with the right config
	heartbeatTicker := time.NewTicker(1 * time.Second)
	heartbeatTimeout := 10 * time.Second
	heartbeatCount := uint64(5)
	var role Role
	if selfID%2 == 0 {
		role = HeartbeatSender
	} else {
		role = HeartbeatReceiver
	}
	senders := make([]uint64, 0)
	receivers := make([]uint64, 0)
	for _, node := range rtc.CommitteeConfig.Nodes {
		if node.ID%2 == 0 {
			senders = append(senders, uint64(node.ID))
		} else {
			receivers = append(receivers, uint64(node.ID))
		}
	}
	c.heartbeatMonitor = NewHeartbeatMonitor(c.consensus.Comm.(MessageSender), heartbeatTicker.C, logger, heartbeatTimeout, heartbeatCount, role, senders, receivers)

	c.consensus.Signer = &Signer{
		ID:               c.Config.SelfID,
		Logger:           flogging.MustGetLogger("orderer.consensus.smartbft.signer").With(zap.String("channel", c.support.ChainID())),
		SignerSerializer: c.SignerSerializer,
		LastConfigBlockNum: func(block *common.Block) uint64 {
			if isConfigBlock(block) {
				return block.Header.Number
			}

			return c.RuntimeConfig.Load().(RuntimeConfig).LastConfigBlock.Header.Number
		},
		HeartbeatMonitor: c.heartbeatMonitor,
	}

	// Setup communication with list of remotes notes for the new channel
	c.Comm.Configure(c.support.ChainID(), rtc.RemoteNodes)

	if err := c.consensus.ValidateConfiguration(rtc.Nodes); err != nil {
		return nil, errors.Wrap(err, "failed to verify SmartBFT-Go configuration")
	}

	logger.Infof("SmartBFT-v3 is now servicing chain %s", support.ChainID())

	return c, nil
}

func bftSmartConsensusBuild(
	c *BFTChain,
	requestInspector *RequestInspector,
) *smartbft.Consensus {
	var err error

	rtc := c.RuntimeConfig.Load().(RuntimeConfig)

	latestMetadata, err := getViewMetadataFromBlock(rtc.LastBlock)
	if err != nil {
		c.Logger.Panicf("Failed extracting view metadata from ledger: %v", err)
	}

	var consensusWAL *wal.WriteAheadLogFile
	var walInitState [][]byte

	c.Logger.Infof("Initializing a WAL for chain %s, on dir: %s", c.support.ChainID(), c.WALDir)
	consensusWAL, walInitState, err = wal.InitializeAndReadAll(c.Logger, c.WALDir, wal.DefaultOptions())
	if err != nil {
		c.Logger.Panicf("failed to initialize a WAL for chain %s, err %s", c.support.ChainID(), err)
	}

	clusterSize := uint64(len(rtc.Nodes))

	// report cluster size
	c.Metrics.ClusterSize.Set(float64(clusterSize))

	sync := &Synchronizer{
		selfID:          rtc.id,
		BlockToDecision: c.blockToDecision,
		OnCommit:        c.updateRuntimeConfig,
		Support:         c.support,
		BlockPuller:     c.BlockPuller,
		ClusterSize:     clusterSize,
		Logger:          c.Logger,
		LatestConfig: func() (types.Configuration, []uint64) {
			rtc := c.RuntimeConfig.Load().(RuntimeConfig)
			return rtc.BFTConfig, rtc.Nodes
		},
	}

	channelDecorator := zap.String("channel", c.support.ChainID())
	logger := flogging.MustGetLogger("orderer.consensus.smartbft.consensus").With(channelDecorator)

	commitZKP := &atomic.Value{}
	cmt := func() []byte {
		feedback, _, err := c.cs.Process(rtc.CommitteeState, committee.Input{})
		if err != nil {
			logger.Errorf("Failed processing library: %v", err)
		}
		commitZKP.Store(feedback.Commitment.Proof)
		if feedback.Commitment != nil {
			logger.Infof("Created commit of %d bytes", len(feedback.Commitment.Data))
			return feedback.Commitment.Data
		}
		logger.Infof("Nothing to commit")
		return nil
	}
	c.assembler = &Assembler{
		Commit:          cmt,
		RuntimeConfig:   c.RuntimeConfig,
		VerificationSeq: c.verifier.VerificationSequence,
		Logger:          flogging.MustGetLogger("orderer.consensus.smartbft.assembler").With(channelDecorator),
	}

	consensus := &smartbft.Consensus{
		Config:   c.Config,
		Logger:   logger,
		Verifier: c.verifier,
		// Signer is initialized later (after heartbeat monitor)
		Metadata:          latestMetadata,
		WAL:               consensusWAL,
		WALInitialContent: walInitState, // Read from WAL entries
		Application:       c,
		Assembler:         c.assembler,
		RequestInspector:  requestInspector,
		Synchronizer:      sync,
		Comm: &Egress{
			ConvertMessage: func(m *smartbftprotos.Message, channel string) *orderer.ConsensusRequest {
				msg := bftMsgToClusterMsg(m, channel)
				if prp := m.GetPrePrepare(); prp != nil {
					if rtc.CommitteeMetadata.shouldCommit(int32(rtc.id)) {
						msg.Metadata = commitZKP.Load().([]byte)
					}
				}
				return msg
			},
			RuntimeConfig: c.RuntimeConfig,
			Channel:       c.support.ChainID(),
			Logger:        flogging.MustGetLogger("orderer.consensus.smartbft.egress").With(channelDecorator),
			RPC: &cluster.RPC{
				Logger:        flogging.MustGetLogger("orderer.consensus.smartbft.rpc").With(channelDecorator),
				Channel:       c.support.ChainID(),
				StreamsByType: cluster.NewStreamsByType(),
				Comm:          c.Comm,
				Timeout:       5 * time.Minute, // Externalize configuration
			},
		},
		Scheduler:         time.NewTicker(time.Second).C,
		ViewChangerTicker: time.NewTicker(time.Second).C,
	}

	proposal, signatures := c.lastPersistedProposalAndSignatures()
	if proposal != nil {
		consensus.LastProposal = *proposal
		consensus.LastSignatures = signatures
	}

	c.reportIsLeader(proposal) // report the leader

	return consensus
}

func buildVerifier(
	cv ConfigValidator,
	runtimeConfig *atomic.Value,
	support consensus.ConsenterSupport,
	requestInspector *RequestInspector,
	policyManager policies.Manager,
) *Verifier {
	channelDecorator := zap.String("channel", support.ChainID())
	logger := flogging.MustGetLogger("orderer.consensus.smartbft.verifier").With(channelDecorator)
	return &Verifier{
		ConfigValidator:       cv,
		VerificationSequencer: support,
		ReqInspector:          requestInspector,
		Logger:                logger,
		RuntimeConfig:         runtimeConfig,
		ConsenterVerifier: &consenterVerifier{
			logger:        logger,
			channel:       support.ChainID(),
			policyManager: policyManager,
		},

		AccessController: &chainACL{
			policyManager: policyManager,
			Logger:        logger,
		},
		Ledger: support,
	}
}

func (c *BFTChain) HandleMessage(sender uint64, m *smartbftprotos.Message, metadata []byte) {
	c.Logger.Debugf("Message from %d", sender)
	/*
		if prp := m.GetPrePrepare(); prp != nil {

			err := c.cs.VerifyCommitment(committee.Commitment{}) // TODO: actually extract the commitment from the pre-prepare
			if err != nil {
				c.Logger.Warningf("Failed verifying commitment of pre-prepare: %v", err)
				return
			}

		}
		if cmt := m.GetCommit(); cmt != nil {
			err := c.cs.VerifyReconShare(committee.ReconShare{}) // TODO: actually extract the ReconShare and ZKP from the commitment
			if err != nil {
				c.Logger.Warningf("Failed verifying ReconShare of commit: %v", err)
				return
			}
		}
	*/

	c.consensus.HandleMessage(sender, m)
}

func (c *BFTChain) HandleRequest(sender uint64, req []byte) {
	c.Logger.Debugf("HandleRequest from %d", sender)
	c.consensus.SubmitRequest(req)
}

func (c *BFTChain) HandleHeartbeat(sender uint64) {
	c.Logger.Debugf("HandleHeartbeat from %d", sender)
	c.heartbeatMonitor.ProcessHeartbeat(sender)
}

func (c *BFTChain) Deliver(proposal types.Proposal, signatures []types.Signature) types.Reconfig {
	block, err := ProposalToBlock(proposal)
	if err != nil {
		c.Logger.Panicf("failed to read proposal, err: %s", err)
	}

	var sigs []*common.MetadataSignature
	var ordererBlockMetadata []byte

	var signers []uint64

	for _, s := range signatures {
		sig := &Signature{}
		if err := sig.Unmarshal(s.Msg); err != nil {
			c.Logger.Errorf("Failed unmarshaling signature from %d: %v", s.ID, err)
			c.Logger.Errorf("Offending signature Msg: %s", base64.StdEncoding.EncodeToString(s.Msg))
			c.Logger.Errorf("Offending signature Value: %s", base64.StdEncoding.EncodeToString(s.Value))
			c.Logger.Errorf("Halting chain.")
			c.Halt()
			return types.Reconfig{}
		}

		if ordererBlockMetadata == nil {
			ordererBlockMetadata = sig.OrdererBlockMetadata
		}

		sigs = append(sigs, &common.MetadataSignature{
			CommitteeAuxiliaryInput: sig.CommitteeAuxiliaryInput,
			AuxiliaryInput:          sig.AuxiliaryInput,
			Signature:               s.Value,
			// We do not put a signature header when we commit the block.
			// Instead, we put the nonce and the identifier and at validation
			// we reconstruct the signature header at runtime.
			// SignatureHeader: sig.SignatureHeader,
			Nonce:    sig.Nonce,
			SignerId: s.ID,
		})

		signers = append(signers, s.ID)
	}

	block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = utils.MarshalOrPanic(&common.Metadata{
		Value:      ordererBlockMetadata,
		Signatures: sigs,
	})

	var mdTotalSize int
	for _, md := range block.Metadata.Metadata {
		mdTotalSize += len(md)
	}

	c.Logger.Infof("Delivering proposal, writing block %d with %d transactions and metadata of total size %d with signatures from %v to the ledger, node id %d",
		block.Header.Number,
		len(block.Data.Data),
		mdTotalSize,
		signers,
		c.Config.SelfID)
	c.Metrics.CommittedBlockNumber.Set(float64(block.Header.Number)) // report the committed block number
	c.reportIsLeader(&proposal)                                      // report the leader
	if utils.IsConfigBlock(block) {

		c.support.WriteConfigBlock(block, nil)
	} else {
		c.support.WriteBlock(block, nil)
	}

	// TODO: call c.cs.Process() with the commitment from the block

	reconfig := c.updateRuntimeConfig(block)
	return reconfig
}

func (c *BFTChain) reportIsLeader(proposal *types.Proposal) {
	var viewNum uint64
	if proposal.Metadata == nil { // genesis block
		viewNum = 0
	} else {
		proposalMD := &smartbftprotos.ViewMetadata{}
		if err := proto.Unmarshal(proposal.Metadata, proposalMD); err != nil {
			c.Logger.Panicf("Failed unmarshaling smartbft metadata from proposal: %v", err)
		}
		viewNum = proposalMD.ViewId
	}

	nodes := c.RuntimeConfig.Load().(RuntimeConfig).Nodes
	n := uint64(len(nodes))
	leaderID := nodes[viewNum%n] // same calculation as done in the library

	c.Metrics.LeaderID.Set(float64(leaderID))

	if leaderID == c.Config.SelfID {
		c.Metrics.IsLeader.Set(1)
	} else {
		c.Metrics.IsLeader.Set(0)
	}

}

func (c *BFTChain) updateRuntimeConfig(block *common.Block) types.Reconfig {
	prevRTC := c.RuntimeConfig.Load().(RuntimeConfig)
	newRTC, err := prevRTC.BlockCommitted(block)
	if err != nil {
		c.Logger.Errorf("Failed constructing RuntimeConfig from block %d, halting chain", block.Header.Number)
		c.Halt()
		return types.Reconfig{}
	}
	c.RuntimeConfig.Store(newRTC)
	if utils.IsConfigBlock(block) {
		c.Comm.Configure(c.Channel, newRTC.RemoteNodes)
	}

	membershipDidNotChange := reflect.DeepEqual(newRTC.Nodes, prevRTC.Nodes)
	configDidNotChange := reflect.DeepEqual(newRTC.BFTConfig, prevRTC.BFTConfig)
	noChangeDetected := membershipDidNotChange && configDidNotChange
	return types.Reconfig{
		InLatestDecision: !noChangeDetected,
		CurrentNodes:     newRTC.Nodes,
		CurrentConfig:    newRTC.BFTConfig,
	}
}

func (c *BFTChain) Order(env *common.Envelope, configSeq uint64) error {
	seq := c.support.Sequence()
	if configSeq < seq {
		c.Logger.Warnf("Normal message was validated against %d, although current config seq has advanced (%d)", configSeq, seq)
		if _, err := c.support.ProcessNormalMsg(env); err != nil {
			return errors.Errorf("bad normal message: %s", err)
		}
	}

	return c.submit(env, configSeq)
}

func (c *BFTChain) Configure(config *common.Envelope, configSeq uint64) error {
	// TODO: check configuration update validity
	seq := c.support.Sequence()
	if configSeq < seq {
		c.Logger.Warnf("Normal message was validated against %d, although current config seq has advanced (%d)", configSeq, seq)
		if configEnv, _, err := c.support.ProcessConfigMsg(config); err != nil {
			return errors.Errorf("bad normal message: %s", err)
		} else {
			return c.submit(configEnv, configSeq)
		}
	}

	return c.submit(config, configSeq)
}

func (c *BFTChain) submit(env *common.Envelope, configSeq uint64) error {
	reqBytes, err := proto.Marshal(env)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal request envelope")
	}

	c.Logger.Debugf("Consensus.SubmitRequest, node id %d", c.Config.SelfID)
	c.consensus.SubmitRequest(reqBytes)
	return nil
}

func (c *BFTChain) WaitReady() error {
	return nil
}

func (c *BFTChain) Errored() <-chan struct{} {
	// TODO: Implement Errored
	return nil
}

func (c *BFTChain) Start() {
	c.consensus.Start()
	c.heartbeatMonitor.Start()
}

func (c *BFTChain) Halt() {
	c.Logger.Infof("Shutting down chain")
	c.heartbeatMonitor.Close()
	c.consensus.Stop()
}

func (c *BFTChain) lastPersistedProposalAndSignatures() (*types.Proposal, []types.Signature) {
	lastBlock := LastBlockFromLedgerOrPanic(c.support, c.Logger)
	// initial report of the last committed block number
	c.Metrics.CommittedBlockNumber.Set(float64(lastBlock.Header.Number))
	decision := c.blockToDecision(lastBlock)
	return &decision.Proposal, decision.Signatures
}

func (c *BFTChain) blockToProposalWithoutSignaturesInMetadata(block *common.Block) types.Proposal {
	blockClone := proto.Clone(block).(*common.Block)
	if len(blockClone.Metadata.Metadata) > int(common.BlockMetadataIndex_SIGNATURES) {
		signatureMetadata := &common.Metadata{}
		// Nil out signatures because we carry them around separately in the library format.
		proto.Unmarshal(blockClone.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata)
		signatureMetadata.Signatures = nil
		blockClone.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = utils.MarshalOrPanic(signatureMetadata)
	}
	prop := types.Proposal{
		Header: blockClone.Header.Bytes(),
		Payload: (&ByteBufferTuple{
			A: utils.MarshalOrPanic(blockClone.Data),
			B: utils.MarshalOrPanic(blockClone.Metadata),
		}).ToBytes(),
		VerificationSequence: int64(c.verifier.VerificationSequence()),
	}

	if isConfigBlock(block) {
		prop.VerificationSequence--
	}

	return prop
}

func (c *BFTChain) blockToDecision(block *common.Block) *types.Decision {
	proposal := c.blockToProposalWithoutSignaturesInMetadata(block)
	if block.Header.Number == 0 {
		return &types.Decision{
			Proposal: proposal,
		}
	}

	signatureMetadata := &common.Metadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata); err != nil {
		c.Logger.Panicf("Failed unmarshaling signatures from block metadata: %v", err)
	}

	ordererMDFromBlock := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMDFromBlock); err != nil {
		c.Logger.Panicf("Failed unmarshaling OrdererBlockMetadata from block signature metadata: %v", err)
	}

	proposal.Metadata = ordererMDFromBlock.ConsenterMetadata

	var signatures []types.Signature
	for _, sigMD := range signatureMetadata.Signatures {
		id := sigMD.SignerId
		sig := &Signature{
			Nonce:                sigMD.Nonce,
			BlockHeader:          block.Header.Bytes(),
			OrdererBlockMetadata: signatureMetadata.Value,
			AuxiliaryInput:       sigMD.AuxiliaryInput,
		}
		prpf := &smartbftprotos.PreparesFrom{}
		if err := proto.Unmarshal(sigMD.AuxiliaryInput, prpf); err != nil {
			c.Logger.Errorf("Failed unmarshaling auxiliary data")
			continue
		}
		c.Logger.Infof("AuxiliaryInput[%d]: %v", id, prpf)
		signatures = append(signatures, types.Signature{
			Msg:   sig.Marshal(),
			Value: sigMD.Signature,
			ID:    id,
		})
	}

	return &types.Decision{
		Signatures: signatures,
		Proposal:   proposal,
	}
}

func (c *BFTChain) blockToID2Identities(block *common.Block) NodeIdentitiesByID {
	env := &common.Envelope{}
	if err := proto.Unmarshal(block.Data.Data[0], env); err != nil {
		c.Logger.Panicf("Failed unmarshaling envelope of previous config block: %v", err)
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(env)
	if err != nil {
		c.Logger.Panicf("Failed getting a new bundle from envelope of previous config block: %v", err)
	}
	oc, _ := bundle.OrdererConfig()
	if oc == nil {
		c.Logger.Panicf("Orderer config of previous config block is nil")
	}
	m := &smartbft2.ConfigMetadata{}
	if err := proto.Unmarshal(oc.ConsensusMetadata(), m); err != nil {
		c.Logger.Panicf("Failed to unmarshal consensus metadata: %v", err)
	}
	id2Identies := map[uint64][]byte{}
	for _, consenter := range m.Consenters {
		sanitizedID, err := crypto.SanitizeIdentity(consenter.Identity)
		if err != nil {
			c.Logger.Panicf("Failed to sanitize identity: %v", err)
		}
		id2Identies[consenter.ConsenterId] = sanitizedID
	}
	return id2Identies
}

type chainACL struct {
	policyManager policies.Manager
	Logger        *flogging.FabricLogger
}

func (c *chainACL) Evaluate(signatureSet []*common.SignedData) error {
	policy, ok := c.policyManager.GetPolicy(policies.ChannelWriters)
	if !ok {
		return fmt.Errorf("could not find policy %s", policies.ChannelWriters)
	}

	err := policy.Evaluate(signatureSet)
	if err != nil {
		c.Logger.Debugf("SigFilter evaluation failed: %s, policyName: %s", err.Error(), policies.ChannelWriters)
		return errors.Wrap(errors.WithStack(msgprocessor.ErrPermissionDenied), err.Error())
	}
	return nil

}
