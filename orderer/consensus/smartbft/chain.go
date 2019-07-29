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
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/core/policy"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/msgprocessor"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// BlockPuller is used to pull blocks from other OSN
type BlockPuller interface {
	PullBlock(seq uint64) *common.Block
	HeightsByEndpoints() (map[string]uint64, error)
	Close()
}

// BFTChain implements Chain interface to wire with
// BFT smart library
type BFTChain struct {
	SelfID           uint64
	Logger           *flogging.FabricLogger
	Consensus        *smartbft.Consensus
	BlockPuller      BlockPuller
	Comm             cluster.Communicator
	SignerSerializer identity.SignerSerializer
	PolicyManager    policy.PolicyManager
	RemoteNodes      []cluster.RemoteNode
	ID2Identities    NodeIdentitiesByID
	support          consensus.ConsenterSupport
	verifier         *Verifier
}

func (c *BFTChain) HandleMessage(sender uint64, m *smartbftprotos.Message) {
	c.Logger.Debugf("HandleMessage from %d, local node id", sender, c.SelfID)
	c.Consensus.HandleMessage(sender, m)
}

func (c *BFTChain) HandleRequest(sender uint64, req []byte) {
	c.Logger.Debugf("HandleRequest from %d, local node id", sender, c.SelfID)
	c.Consensus.SubmitRequest(req)
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

	block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&common.Metadata{
		Value:      ordererBlockMetadata,
		Signatures: sigs,
	})

	c.Logger.Debugf("Delivering proposal, writing block %d to the ledger, node id %d", block.Header.Number, c.SelfID)
	if protoutil.IsConfigBlock(block) {
		c.support.WriteConfigBlock(block, nil)
		return
	}
	c.support.WriteBlock(block, nil)
	c.verifier.LastCommittedBlockHash = hex.EncodeToString(protoutil.BlockHeaderHash(block.Header))
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
	c.Consensus.SubmitRequest(reqBytes)
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
	requestInspector := &RequestInspector{
		ValidateIdentityStructure: func(_ *msp.SerializedIdentity) error {
			return nil
		},
	}

	// Number of replica set nodes
	clusterSize := uint64(len(c.RemoteNodes)) + 1 // +1 for current node as not counted among remote nodes

	var nodes []uint64
	for _, n := range c.RemoteNodes {
		nodes = append(nodes, n.ID)
	}

	c.verifier = &Verifier{
		VerificationSequencer: c.support,
		ReqInspector:          requestInspector,
		Logger:                flogging.MustGetLogger("orderer.consensus.smartbft.verifier"),
		Id2Identity:           c.ID2Identities,
		BlockVerifier: &cluster.BlockValidationPolicyVerifier{
			Logger:    flogging.MustGetLogger("orderer.consensus.smartbft.verifier.block"),
			Channel:   c.support.ChainID(),
			PolicyMgr: c.PolicyManager,
		},
		AccessController: &chainACL{
			policyManager: c.PolicyManager,
			Logger:        c.Logger,
		},
		Ledger: c.support,
	}

	if c.verifier.LastCommittedBlockHash == "" {
		lastBlock := lastBlockFromLedgerOrPanic(c.support, c.Logger)
		c.verifier.LastCommittedBlockHash = hex.EncodeToString(protoutil.BlockHeaderHash(lastBlock.Header))
	}

	c.Consensus = &smartbft.Consensus{
		SelfID:       c.SelfID,
		N:            clusterSize,
		BatchSize:    1,
		BatchTimeout: 5 * time.Second,
		Logger:       flogging.MustGetLogger("orderer.consensus.smartbft.consensus"),
		Verifier:     c.verifier,
		Signer: &Signer{
			ID:               c.SelfID,
			Logger:           flogging.MustGetLogger("orderer.consensus.smartbft.signer"),
			SignerSerializer: c.SignerSerializer,
		},
		// TODO: Change WAL into regular one
		WAL:         &wal.EphemeralWAL{},
		Application: c,
		Assembler: &Assembler{
			Logger: flogging.MustGetLogger("orderer.consensus.smartbft.assembler"),
			Ledger: c.support,
		},
		RequestInspector: requestInspector,
		Synchronizer: &Synchronizer{
			support:     c.support,
			clusterSize: clusterSize,
			logger:      flogging.MustGetLogger("orderer.consensus.smartbft.synchronizer"),
			blockPuller: c.BlockPuller,
		},
		Comm: &Egress{
			Channel: c.support.ChainID(),
			Logger:  flogging.MustGetLogger("orderer.consensus.smartbft.egress"),
			RPC: &cluster.RPC{
				Logger:        flogging.MustGetLogger("orderer.consensus.smartbft.rpc"),
				Channel:       c.support.ChainID(),
				StreamsByType: cluster.NewStreamsByType(),
				Comm:          c.Comm,
				Timeout:       5 * time.Minute, // Externalize configuration
			},
		},
	}

	// Setup communication with list of remotes notes for the new channel
	c.Logger.Debugf("Configure cluster communication with remote nodes [%+v]")
	c.Comm.Configure(c.support.ChainID(), c.RemoteNodes)
	c.Consensus.Start()
}

func (c *BFTChain) Halt() {

}

type chainACL struct {
	policyManager policies.Manager
	Logger        *flogging.FabricLogger
}

func (c *chainACL) Evaluate(signatureSet []*protoutil.SignedData) error {
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
