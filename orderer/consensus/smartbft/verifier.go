/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/hex"

	"sync"

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

type requestVerifier func(req []byte) (types.RequestInfo, error)

type NodeIdentitiesByID map[uint64][]byte

type Verifier struct {
	ReqInspector          RequestInspector
	Id2Identity           NodeIdentitiesByID
	BlockVerifier         BlockVerifier
	AccessController      AccessController
	VerificationSequencer Sequencer
	Logger                PanicLogger
}

func (v *Verifier) VerifyProposal(proposal types.Proposal, prevHeader []byte) ([]types.RequestInfo, error) {
	block, err := proposalToBlock(proposal)
	if err != nil {
		return nil, err
	}

	if err := verifyBlockHeader(block, prevHeader, v.Logger); err != nil {
		return nil, err
	}

	requests, err := verifyBlockDataAndMetadata(block, v.VerifyRequest, v.VerificationSequence(), proposal.Metadata)
	if err != nil {
		return nil, err
	}

	return requests, nil
}

func (v *Verifier) VerifyRequest(rawRequest []byte) (types.RequestInfo, error) {
	req, err := v.ReqInspector.unwrapReq(rawRequest)
	if err != nil {
		return types.RequestInfo{}, err
	}

	err = v.AccessController.Evaluate([]*protoutil.SignedData{
		{Identity: req.sigHdr.Creator, Data: req.envelope.Payload, Signature: req.envelope.Signature},
	})

	if err != nil {
		return types.RequestInfo{}, errors.Wrap(err, "access denied")
	}

	return v.ReqInspector.requestIDFromSigHeader(req.sigHdr)
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

func verifyBlockDataAndMetadata(block *common.Block, verifyReq requestVerifier, verificationSeq uint64, metadata []byte) ([]types.RequestInfo, error) {
	if block.Data == nil || len(block.Data.Data) == 0 {
		return nil, errors.New("empty block data")
	}

	if block.Metadata == nil || len(block.Metadata.Metadata) < len(common.BlockMetadataIndex_name) {
		return nil, errors.New("block metadata is either missing or contains too few entries")
	}

	lastConfig, err := protoutil.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch last config from block")
	}

	if verificationSeq != lastConfig {
		return nil, errors.Errorf("last config in proposal is %d, expecting %d", lastConfig, verificationSeq)
	}

	metadataInBlock := &smartbftprotos.ViewMetadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER], metadataInBlock); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling smartbft metadata from block")
	}

	metadataFromProposal := &smartbftprotos.ViewMetadata{}
	if err := proto.Unmarshal(metadata, metadataInBlock); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling smartbft metadata from proposal")
	}

	if !proto.Equal(metadataInBlock, metadataFromProposal) {
		return nil, errors.Errorf("expected metadata in block to be %v but got %v", metadataFromProposal, metadataInBlock)
	}

	return validateTransactions(block.Data.Data, verifyReq)
}

func validateTransactions(blockData [][]byte, verifyReq requestVerifier) ([]types.RequestInfo, error) {
	var validationFinished sync.WaitGroup
	validationFinished.Add(len(blockData))

	type txnValidation struct {
		indexInBlock  int
		extractedInfo types.RequestInfo
		validationErr error
	}

	validations := make(chan txnValidation, len(blockData))
	for i, payload := range blockData {
		go func(indexInBlock int, payload []byte) {
			defer validationFinished.Done()
			reqInfo, err := verifyReq(payload)
			validations <- txnValidation{
				indexInBlock:  indexInBlock,
				extractedInfo: reqInfo,
				validationErr: err,
			}
		}(i, payload)
	}

	validationFinished.Wait()
	close(validations)

	indexToRequestInfo := make(map[int]types.RequestInfo)
	for validationResult := range validations {
		indexToRequestInfo[validationResult.indexInBlock] = validationResult.extractedInfo
		if validationResult.validationErr != nil {
			return nil, validationResult.validationErr
		}
	}

	var res []types.RequestInfo
	for indexInBlock := range blockData {
		res = append(res, indexToRequestInfo[indexInBlock])
	}

	return res, nil
}
