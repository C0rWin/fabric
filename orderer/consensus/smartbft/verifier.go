/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"bytes"
	"encoding/hex"
	"sync"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

// Sequencer returns sequences
type Sequencer interface {
	Sequence() uint64
}

// BlockVerifier verifies block signatures
type BlockVerifier interface {
	VerifyBlockSignature(sd []*common.SignedData, _ *common.ConfigEnvelope) error
}

// AccessController is used to determine if a signature of a certain client is valid
type AccessController interface {
	// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
	Evaluate(signatureSet []*common.SignedData) error
}

type requestVerifier func(req []byte) (types.RequestInfo, error)

type NodeIdentitiesByID map[uint64][]byte

func (nibd NodeIdentitiesByID) IdentityToID(identity []byte) (uint64, bool) {
	sID := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(identity, sID); err != nil {
		panic(err)
	}
	for id, currIdentity := range nibd {
		currentID := &msp.SerializedIdentity{}
		proto.Unmarshal(currIdentity, currentID)
		if proto.Equal(currentID, sID) {
			return id, true
		}
	}
	return 0, false
}

type Verifier struct {
	ReqInspector           *RequestInspector
	Id2Identity            NodeIdentitiesByID
	BlockVerifier          BlockVerifier
	AccessController       AccessController
	VerificationSequencer  Sequencer
	Ledger                 Ledger
	LastCommittedBlockHash string
	Logger                 *flogging.FabricLogger
	lock                   sync.RWMutex
}

func (v *Verifier) VerifyProposal(proposal types.Proposal) ([]types.RequestInfo, error) {
	block, err := ProposalToBlock(proposal)
	if err != nil {
		return nil, err
	}

	if err := verifyHashChain(block, v.lastCommittedHash()); err != nil {
		return nil, err
	}

	requests, err := v.verifyBlockDataAndMetadata(block, proposal.Metadata)
	if err != nil {
		return nil, err
	}

	return requests, nil
}

func (v *Verifier) VerifySignature(signature types.Signature) error {
	identity, exists := v.Id2Identity[signature.Id]
	if !exists {
		return errors.Errorf("node with id of %d doesn't exist", signature.Id)
	}

	return v.AccessController.Evaluate([]*common.SignedData{
		{Identity: identity, Data: signature.Msg, Signature: signature.Value},
	})
}

func (v *Verifier) VerifyRequest(rawRequest []byte) (types.RequestInfo, error) {
	req, err := v.ReqInspector.unwrapReq(rawRequest)
	if err != nil {
		return types.RequestInfo{}, err
	}

	err = v.AccessController.Evaluate([]*common.SignedData{
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
	// TODO: check error
	sig.Unmarshal(signature.Msg)

	if err := v.verifySignatureIsBoundToProposal(sig, identity, prop); err != nil {
		return err
	}

	expectedMsgToBeSigned := util.ConcatenateBytes(sig.OrdererBlockMetadata, sig.SignatureHeader, sig.BlockHeader)
	return v.BlockVerifier.VerifyBlockSignature([]*common.SignedData{{
		Signature: signature.Value,
		Data:      expectedMsgToBeSigned,
		Identity:  identity,
	}}, nil)
}

func (v *Verifier) VerificationSequence() uint64 {
	return v.VerificationSequencer.Sequence()
}

func (v *Verifier) lastCommittedHash() string {
	v.lock.RLock()
	defer v.lock.RUnlock()
	return v.LastCommittedBlockHash
}

func verifyHashChain(block *common.Block, prevHeaderHash string) error {
	thisHdrHashOfPrevHdr := hex.EncodeToString(block.Header.PreviousHash)
	if prevHeaderHash != thisHdrHashOfPrevHdr {
		return errors.Errorf("previous header hash is %s but expected %s", thisHdrHashOfPrevHdr, prevHeaderHash)
	}

	dataHash := hex.EncodeToString(block.Header.DataHash)
	actualHashOfData := hex.EncodeToString(block.Data.Hash())
	if dataHash != actualHashOfData {
		return errors.Errorf("data hash is %s but expected %s", dataHash, actualHashOfData)
	}
	return nil
}

func (v *Verifier) verifyBlockDataAndMetadata(block *common.Block, metadata []byte) ([]types.RequestInfo, error) {
	if block.Data == nil || len(block.Data.Data) == 0 {
		return nil, errors.New("empty block data")
	}

	if block.Metadata == nil || len(block.Metadata.Metadata) < len(common.BlockMetadataIndex_name) {
		return nil, errors.New("block metadata is either missing or contains too few entries")
	}

	lastConfig, err := utils.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch last config from block")
	}

	configBlock := v.Ledger.Block(lastConfig)
	configEnvelope, err := ConfigurationEnvelop(configBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal configuration payload")
	}

	if v.VerificationSequence() != configEnvelope.Config.Sequence {
		return nil, errors.Errorf("last config in proposal is %d, expecting %d", configEnvelope.Config.Sequence, v.VerificationSequence())
	}

	signatureMetadata, err := utils.GetMetadataFromBlock(block, common.BlockMetadataIndex_SIGNATURES)
	if err != nil {
		return nil, err
	}
	ordererMetadataFromSignature := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMetadataFromSignature); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling OrdererBlockMetadata")
	}

	// Ensure the view metadata in the block signature and in the proposal are the same

	metadataInBlock := &smartbftprotos.ViewMetadata{}
	if err := proto.Unmarshal(ordererMetadataFromSignature.ConsenterMetadata, metadataInBlock); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling smartbft metadata from block")
	}

	metadataFromProposal := &smartbftprotos.ViewMetadata{}
	if err := proto.Unmarshal(metadata, metadataFromProposal); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling smartbft metadata from proposal")
	}

	if !proto.Equal(metadataInBlock, metadataFromProposal) {
		return nil, errors.Errorf("expected metadata in block to be %v but got %v", metadataFromProposal, metadataInBlock)
	}

	// Verify last config

	if ordererMetadataFromSignature.LastConfig == nil {
		return nil, errors.Errorf("last config is nil")
	}

	if ordererMetadataFromSignature.LastConfig.Index != lastConfig {
		return nil, errors.Errorf("last config in block orderer metadata points to %d but our persisted last config is %d", ordererMetadataFromSignature.LastConfig.Index, lastConfig)
	}

	rawLastConfig, err := utils.GetMetadataFromBlock(block, common.BlockMetadataIndex_LAST_CONFIG)
	if err != nil {
		return nil, err
	}
	lastConf := &common.LastConfig{}
	if err := proto.Unmarshal(rawLastConfig.Value, lastConf); err != nil {
		return nil, err
	}
	if lastConf.Index != lastConfig {
		return nil, errors.Errorf("last config in block metadata points to %d but our persisted last config is %d", ordererMetadataFromSignature.LastConfig.Index, lastConfig)
	}

	return validateTransactions(block.Data.Data, v.VerifyRequest)
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

func (v *Verifier) verifySignatureIsBoundToProposal(sig *Signature, identity []byte, prop types.Proposal) error {
	// We verify the following fields:
	// ConsenterMetadata    []byte
	// SignatureHeader      []byte
	// BlockHeader          []byte
	// OrdererBlockMetadata []byte

	// Ensure block header is equal
	if !bytes.Equal(prop.Header, sig.BlockHeader) {
		return errors.Errorf("mismatched block header")
	}

	// Ensure signature header matches the identity
	sigHdr := &common.SignatureHeader{}
	if err := proto.Unmarshal(sig.SignatureHeader, sigHdr); err != nil {
		return errors.Wrap(err, "malformed signature header")
	}
	if !bytes.Equal(sigHdr.Creator, identity) {
		return errors.Errorf("identity in signature header does not match expected identity")
	}

	// Ensure orderer block metadata's consenter MD matches the proposal
	ordererMD := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(sig.OrdererBlockMetadata, ordererMD); err != nil {
		return errors.Wrap(err, "malformed orderer metadata in signature")
	}

	if !bytes.Equal(ordererMD.ConsenterMetadata, prop.Metadata) {
		return errors.Errorf("consenter metadata in OrdererBlockMetadata doesn't match proposal")
	}

	block, err := ProposalToBlock(prop)
	if err != nil {
		v.Logger.Warnf("got malformed proposal: %v", err)
		return err
	}

	// Ensure Metadata slice is of the right size
	if len(block.Metadata.Metadata) != len(common.BlockMetadataIndex_name) {
		return errors.Errorf("block metadata is of size %d but should be of size %d",
			len(block.Metadata.Metadata), len(common.BlockMetadataIndex_name))
	}

	signatureMetadata := &common.Metadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata); err != nil {
		return errors.Wrap(err, "malformed signature metadata")
	}

	ordererMDFromBlock := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(sig.OrdererBlockMetadata, ordererMDFromBlock); err != nil {
		return errors.Wrap(err, "malformed orderer metadata in block")
	}

	// Ensure the block's OrdererBlockMetadata matches the signature.
	if !proto.Equal(ordererMDFromBlock, ordererMD) {
		return errors.Errorf("signature's OrdererBlockMetadata and OrdererBlockMetadata extracted from block do not match")
	}

	// TODO: Check last config block

	return nil
}
