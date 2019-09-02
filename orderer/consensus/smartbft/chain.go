/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/hex"
	"fmt"
	"time"

	smartbft "github.com/SmartBFT-Go/consensus/pkg/consensus"
	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/pkg/wal"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/msgprocessor"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
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

// Config consensus specific configuration parameters
type Config struct {
	WALDir            string // WAL data of <my-channel> is stored in WALDir/<my-channel>
	SnapDir           string // Snapshots of <my-channel> are stored in SnapDir/<my-channel>
	EvictionSuspicion string // Duration threshold that the node samples in order to suspect its eviction from the channel.
}

// BFTChain implements Chain interface to wire with
// BFT smart library
type BFTChain struct {
	channel          string
	SelfID           uint64
	BlockPuller      BlockPuller
	Comm             cluster.Communicator
	SignerSerializer crypto.LocalSigner
	PolicyManager    policies.Manager
	RemoteNodes      []cluster.RemoteNode
	ID2Identities    NodeIdentitiesByID
	Logger           *flogging.FabricLogger
	WALDir           string

	consensus *smartbft.Consensus
	support   consensus.ConsenterSupport
	verifier  *Verifier
}

// NewChain creates new BFT Smart chain
func NewChain(
	selfID uint64,
	walDir string,
	blockPuller BlockPuller,
	comm cluster.Communicator,
	signerSerializer crypto.LocalSigner,
	policyManager policies.Manager,
	remoteNodes []cluster.RemoteNode,
	id2Identities NodeIdentitiesByID,
	support consensus.ConsenterSupport,
) *BFTChain {

	requestInspector := &RequestInspector{
		ValidateIdentityStructure: func(_ *msp.SerializedIdentity) error {
			return nil
		},
	}

	var nodes []uint64
	for _, n := range remoteNodes {
		nodes = append(nodes, n.ID)
	}
	nodes = append(nodes, selfID)

	logger := flogging.MustGetLogger("orderer.consensus.smartbft.chain").With(zap.String("channel", support.ChainID()))

	c := &BFTChain{
		channel:          support.ChainID(),
		SelfID:           selfID,
		WALDir:           walDir,
		Comm:             comm,
		support:          support,
		SignerSerializer: signerSerializer,
		PolicyManager:    policyManager,
		RemoteNodes:      remoteNodes,
		ID2Identities:    id2Identities,
		BlockPuller:      blockPuller,
		Logger:           logger,
	}

	c.verifier = verifierBuild(support, requestInspector, id2Identities, policyManager)

	if c.verifier.LastCommittedBlockHash == "" {
		lastBlock := lastBlockFromLedgerOrPanic(support, c.Logger)
		c.verifier.LastCommittedBlockHash = hex.EncodeToString(lastBlock.Header.Hash())
	}

	c.consensus = bftSmartConsensusBuild(c, requestInspector, nodes)

	// Setup communication with list of remotes notes for the new channel
	c.Comm.Configure(c.support.ChainID(), c.RemoteNodes)

	return c
}

func bftSmartConsensusBuild(
	c *BFTChain,
	requestInspector *RequestInspector,
	nodes []uint64,
) *smartbft.Consensus {

	var err error
	// TODO: this could be optimized as we already read block to build
	// policy manager configuration, block we read could be re-used here
	// instead going to the ledger once again.
	block := c.support.Block(c.support.Height() - 1)
	latestMetadata, err := getViewMetadataFromBlock(block)
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

	clusterSize := uint64(len(nodes))

	sync := &Synchronizer{
		UpdateLastHash: c.updateLastCommittedHash,
		Support:        c.support,
		BlockPuller:    c.BlockPuller,
		ClusterSize:    clusterSize,
		Logger:         c.Logger,
	}

	channelDecorator := zap.String("channel", c.support.ChainID())
	logger := flogging.MustGetLogger("orderer.consensus.smartbft.consensus").With(channelDecorator)

	config := smartbft.DefaultConfig
	config.LeaderHeartbeatTimeout = time.Second * 10
	config.SelfID = c.SelfID

	consensus := &smartbft.Consensus{
		Config:   config,
		Logger:   logger,
		Verifier: c.verifier,
		Signer: &Signer{
			ID:               c.SelfID,
			Logger:           flogging.MustGetLogger("orderer.consensus.smartbft.signer").With(channelDecorator),
			SignerSerializer: c.SignerSerializer,
		},
		Metadata:          latestMetadata,
		WAL:               consensusWAL,
		WALInitialContent: walInitState, // Read from WAL entries
		Application:       c,
		Assembler: &Assembler{
			Logger: flogging.MustGetLogger("orderer.consensus.smartbft.assembler").With(channelDecorator),
			Ledger: c.support,
		},
		RequestInspector: requestInspector,
		Synchronizer:     sync,
		Comm: &Egress{
			nodes:   nodes,
			Channel: c.support.ChainID(),
			Logger:  flogging.MustGetLogger("orderer.consensus.smartbft.egress").With(channelDecorator),
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

	return consensus
}

func verifierBuild(
	support consensus.ConsenterSupport,
	requestInspector *RequestInspector,
	id2Identities NodeIdentitiesByID,
	policyManager policies.Manager,
) *Verifier {
	channelDecorator := zap.String("channel", support.ChainID())
	return &Verifier{
		VerificationSequencer: support,
		ReqInspector:          requestInspector,
		Logger:                flogging.MustGetLogger("orderer.consensus.smartbft.verifier").With(channelDecorator),
		Id2Identity:           id2Identities,
		BlockVerifier: &cluster.BlockValidationPolicyVerifier{
			Logger:    flogging.MustGetLogger("orderer.consensus.smartbft.verifier.block").With(channelDecorator),
			Channel:   support.ChainID(),
			PolicyMgr: policyManager,
		},
		AccessController: &chainACL{
			policyManager: policyManager,
			Logger:        flogging.MustGetLogger("orderer.consensus.smartbft.accesscontroller").With(channelDecorator),
		},
		Ledger: support,
	}
}

func (c *BFTChain) HandleMessage(sender uint64, m *smartbftprotos.Message) {
	c.Logger.Debugf("Message from %d", sender)
	c.consensus.HandleMessage(sender, m)
}

func (c *BFTChain) HandleRequest(sender uint64, req []byte) {
	c.Logger.Debugf("HandleRequest from %d", sender)
	c.consensus.SubmitRequest(req)
}

func (c *BFTChain) Deliver(proposal types.Proposal, signatures []types.Signature) {
	block, err := ProposalToBlock(proposal)
	if err != nil {
		c.Logger.Panicf("failed to read proposal, err: %s", err)
	}

	var sigs []*common.MetadataSignature
	var ordererBlockMetadata []byte
	for _, s := range signatures {
		sig := &Signature{}
		sig.Unmarshal(s.Msg)

		if ordererBlockMetadata == nil {
			ordererBlockMetadata = sig.OrdererBlockMetadata
		}

		sigs = append(sigs, &common.MetadataSignature{
			Signature:       s.Value,
			SignatureHeader: sig.SignatureHeader,
		})
	}

	block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = utils.MarshalOrPanic(&common.Metadata{
		Value:      ordererBlockMetadata,
		Signatures: sigs,
	})

	defer c.updateLastCommittedHash(block)
	c.Logger.Debugf("Delivering proposal, writing block %d to the ledger, node id %d", block.Header.Number, c.SelfID)
	if utils.IsConfigBlock(block) {
		c.support.WriteConfigBlock(block, nil)
		return
	}
	c.support.WriteBlock(block, nil)
}

func (c *BFTChain) updateLastCommittedHash(block *common.Block) {
	c.verifier.lock.Lock()
	defer c.verifier.lock.Unlock()
	c.verifier.LastCommittedBlockHash = hex.EncodeToString(block.Header.Hash())
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

	c.Logger.Debugf("Consensus.SubmitRequest, node id %d", c.SelfID)
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
}

func (c *BFTChain) Halt() {

}

func (c *BFTChain) lastPersistedProposalAndSignatures() (*types.Proposal, []types.Signature) {
	lastBlock := lastBlockFromLedgerOrPanic(c.support, c.Logger)

	proposal := &types.Proposal{
		Header: lastBlock.Header.Hash(),
		Payload: (&ByteBufferTuple{
			A: utils.MarshalOrPanic(lastBlock.Data),
			B: utils.MarshalOrPanic(lastBlock.Metadata),
		}).ToBytes(),
	}

	if lastBlock.Header.Number == 0 {
		return proposal, nil
	}

	signatureMetadata := &common.Metadata{}
	if err := proto.Unmarshal(lastBlock.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata); err != nil {
		c.Logger.Panicf("Failed unmarshaling signatures from block metadata: %v", err)
	}

	ordererMDFromBlock := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMDFromBlock); err != nil {
		c.Logger.Panicf("Failed unmarshaling OrdererBlockMetadata from block signature metadata: %v", err)
	}

	proposal.Metadata = ordererMDFromBlock.ConsenterMetadata

	var signatures []types.Signature
	for _, sigMD := range signatureMetadata.Signatures {
		sigHdr := &common.SignatureHeader{}
		if err := proto.Unmarshal(sigMD.SignatureHeader, sigHdr); err != nil {
			c.Logger.Panicf("Failed unmarshaling signature header: %v", err)
		}
		id, found := c.ID2Identities.IdentityToID(sigHdr.Creator)
		if !found {
			c.Logger.Panicf("Didn't find identity corresponding to %s", string(sigHdr.Creator))
		}
		sig := &Signature{
			SignatureHeader:      sigMD.SignatureHeader,
			BlockHeader:          lastBlock.Header.Hash(),
			OrdererBlockMetadata: signatureMetadata.Value,
		}
		signatures = append(signatures, types.Signature{
			Msg:   sig.Marshal(),
			Value: sigMD.Signature,
			Id:    id,
		})
	}
	return proposal, signatures
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
