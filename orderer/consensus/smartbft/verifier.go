/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/hex"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// Sequencer returns sequences
type Sequencer interface {
	Sequence() uint64
}

// BlockVerifier verifies block signatures
type BlockVerifier interface {
	VerifyBlockSignature(sd []*protoutil.SignedData, _ *common.ConfigEnvelope) error
}

// AccessController is used to determine if a signature of a certain client is valid
type AccessController interface {
	// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
	Evaluate(signatureSet []*protoutil.SignedData) error
}

type NodeIdentitiesByID map[uint64][]byte

type Verifier struct {
	Id2Identity           NodeIdentitiesByID
	BlockVerifier         BlockVerifier
	AccessController      AccessController
	VerificationSequencer Sequencer
	Logger                PanicLogger
}

func (v *Verifier) VerifyProposal(proposal types.Proposal, prevHeader []byte) error {
	block, err := proposalToBlock(proposal)
	if err != nil {
		return err
	}

	if err := verifyBlockHeader(block, prevHeader, v.Logger); err != nil {
		return err
	}

	if err := verifyBlockDataAndMetadata(block, v.VerifyRequest, v.VerificationSequence(), proposal.Metadata); err != nil {
		return err
	}

	return nil
}

func (v *Verifier) VerifyRequest(val []byte) error {
	envelope, err := protoutil.UnmarshalEnvelope(val)
	if err != nil {
		return err
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return errors.Wrap(err, "failed unmarshaling payload")
	}

	if payload.Header == nil {
		return errors.Errorf("no header in payload")
	}

	sigHdr := &common.SignatureHeader{}
	if err := proto.Unmarshal(payload.Header.SignatureHeader, sigHdr); err != nil {
		return err
	}

	err = v.AccessController.Evaluate([]*protoutil.SignedData{
		{Identity: sigHdr.Creator, Data: envelope.Payload, Signature: envelope.Signature},
	})

	if err != nil {
		return errors.Wrap(err, "access denied")
	}
	return nil
}

func (v *Verifier) VerifyConsenterSig(signature types.Signature, prop types.Proposal) error {
	identity, exists := v.Id2Identity[signature.Id]
	if !exists {
		return errors.Errorf("node with id of %d doesn't exist", signature.Id)
	}

	sig := &Signature{}
	sig.Unmarshal(signature.Msg)

	sigHdr := protoutil.MarshalOrPanic(sig.SignatureHeader)
	expectedMsgToBeSigned := util.ConcatenateBytes(sig.OrdererBlockMetadata, sigHdr, protoutil.BlockHeaderBytes(sig.BlockHeader))
	return v.BlockVerifier.VerifyBlockSignature([]*protoutil.SignedData{{
		Signature: signature.Value,
		Data:      expectedMsgToBeSigned,
		Identity:  identity,
	}}, nil)
}

func (v *Verifier) VerificationSequence() uint64 {
	return v.VerificationSequencer.Sequence()
}

func verifyBlockHeader(block *common.Block, prevHeader []byte, logger PanicLogger) error {
	prevHdr := &common.BlockHeader{}
	if err := proto.Unmarshal(prevHeader, prevHdr); err != nil {
		logger.Panicf("Previous header is malformed: %v", err)
	}
	if block.Header == nil {
		return errors.Errorf("nil block header")
	}

	prevHdrHash := hex.EncodeToString(protoutil.BlockHeaderHash(prevHdr))
	thisHdrHashOfPrevHdr := hex.EncodeToString(block.Header.PreviousHash)
	if prevHdrHash != thisHdrHashOfPrevHdr {
		return errors.Errorf("previous header hash is %s but expected %s", thisHdrHashOfPrevHdr, prevHdrHash)
	}

	dataHash := hex.EncodeToString(block.Header.DataHash)
	actualHashOfData := hex.EncodeToString(protoutil.BlockDataHash(block.Data))
	if dataHash != actualHashOfData {
		return errors.Errorf("data hash is %s but expected %s", dataHash, actualHashOfData)
	}
	return nil
}

func verifyBlockDataAndMetadata(block *common.Block, verifyReq func(req []byte) error, verificationSeq uint64, metadata []byte) error {
	if block.Data == nil || len(block.Data.Data) == 0 {
		return errors.New("empty block data")
	}

	for _, txn := range block.Data.Data {
		if err := verifyReq(txn); err != nil {
			return err
		}
	}

	if block.Metadata == nil || len(block.Metadata.Metadata) < len(common.BlockMetadataIndex_name) {
		return errors.New("block metadata is either missing or contains too few entries")
	}

	lastConfig, err := protoutil.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return errors.Wrap(err, "could not fetch last config from block")
	}

	if verificationSeq != lastConfig {
		return errors.Errorf("last config in proposal is %d, expecting %d", lastConfig, verificationSeq)
	}

	metadataInBlock := &smartbftprotos.BlockMetadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER], metadataInBlock); err != nil {
		return errors.Wrap(err, "failed unmarshaling smartbft metadata from block")
	}

	metadataFromProposal := &smartbftprotos.BlockMetadata{}
	if err := proto.Unmarshal(metadata, metadataInBlock); err != nil {
		return errors.Wrap(err, "failed unmarshaling smartbft metadata from proposal")
	}

	if !proto.Equal(metadataInBlock, metadataFromProposal) {
		return errors.Errorf("expected metadata in block to be %v but got %v", metadataFromProposal, metadataInBlock)
	}

	return nil
}
