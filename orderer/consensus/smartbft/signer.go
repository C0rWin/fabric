/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/asn1"
	"encoding/base64"

	types2 "github.com/hyperledger/fabric/orderer/consensus/smartbft/types"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	"github.com/hyperledger/fabric/protos/utils"
)

//go:generate mockery -dir . -name SignerSerializer -case underscore -output ./mocks/

type SignerSerializer interface {
	crypto.Signer
	crypto.IdentitySerializer
}

//go:generate mockery -dir . -name HeartbeatSuspects -case underscore -output ./mocks/

type HeartbeatSuspects interface {
	GetSuspects() []uint64
}

type Signer struct {
	ID                 uint64
	SignerSerializer   SignerSerializer
	Logger             Logger
	LastConfigBlockNum func(*common.Block) uint64
	HeartbeatMonitor   HeartbeatSuspects
	CreateReconShares  func() []committee.ReconShare
}

func (s *Signer) Sign(msg []byte) []byte {
	signature, err := s.SignerSerializer.Sign(msg)
	if err != nil {
		s.Logger.Panicf("Failed signing message: %v", err)
	}
	return signature
}

func (s *Signer) SignProposal(proposal types.Proposal, auxiliaryInput []byte) *types.Signature {
	block, err := ProposalToBlock(proposal)
	if err != nil {
		s.Logger.Panicf("Tried to sign bad proposal: %v", err)
	}

	nonce := randomNonceOrPanic()

	obm := utils.GetOrdererblockMetadataOrPanic(block)

	cm := &types2.CommitteeMetadata{}
	if err := cm.Unmarshal(obm.CommitteeMetadata); err != nil {
		s.Logger.Panicf("Failed unmarshaling committee metadata on an agreed upon block: %v", err)
	}
	var reconShares [][]byte
	// This is the last block of the committee, so include reconstruction shares.
	if cm.CommitteeShiftAt == int64(block.Header.Number) {
		for _, rcs := range s.CreateReconShares() {
			rawReconshare, err := asn1.Marshal(rcs)
			if err != nil {
				s.Logger.Panicf("Failed serializing reconstruction share: %v", err)
			}
			reconShares = append(reconShares, rawReconshare)
		}
	}

	var suspects []int32
	monitorSuspects := s.HeartbeatMonitor.GetSuspects()
	for _, s := range monitorSuspects {
		suspects = append(suspects, int32(s))
	}
	committeeFeedback := &smartbft.CommitteeFeedback{
		Reconshares: reconShares,
		Suspects:    suspects,
	}
	aux, err := utils.Marshal(committeeFeedback)
	if err != nil {
		s.Logger.Panicf("Failed marshaling committee feedback: %v", err)
	}

	signatureMetadata := &common.Metadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata); err != nil {
		s.Logger.Panicf("Failed unmarshaling Metadata from %s",
			base64.StdEncoding.EncodeToString(block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES]))

	}
	ordererMDFromBlock := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMDFromBlock); err != nil {
		s.Logger.Panicf("Failed unmarshaling OrdererBlockMetadata from %s", base64.StdEncoding.EncodeToString(signatureMetadata.Value))
	}

	sig := Signature{
		CommitteeAuxiliaryInput: aux,
		AuxiliaryInput:          auxiliaryInput,
		Nonce:                   nonce,
		BlockHeader:             block.Header.Bytes(),
		SignatureHeader:         utils.MarshalOrPanic(s.newSignatureHeaderOrPanic(nonce)),
		OrdererBlockMetadata: utils.MarshalOrPanic(&common.OrdererBlockMetadata{
			CommittteeCommitment: ordererMDFromBlock.CommittteeCommitment,
			LastConfig:           &common.LastConfig{Index: s.LastConfigBlockNum(block)},
			ConsenterMetadata:    proposal.Metadata,
			CommitteeMetadata:    obm.CommitteeMetadata,
			HeartbeatSuspects:    ordererMDFromBlock.HeartbeatSuspects,
		}),
	}

	signature := utils.SignOrPanic(s.SignerSerializer, sig.AsBytes())

	// Nil out the signature header after creating the signature
	sig.SignatureHeader = nil

	return &types.Signature{
		ID:    s.ID,
		Value: signature,
		Msg:   sig.Marshal(),
	}
}

// NewSignatureHeader creates a SignatureHeader with the correct signing identity and a valid nonce
func (s *Signer) newSignatureHeaderOrPanic(nonce []byte) *common.SignatureHeader {
	creator, err := s.SignerSerializer.Serialize()
	if err != nil {
		panic(err)
	}

	return &common.SignatureHeader{
		Creator: creator,
		Nonce:   nonce,
	}
}

func randomNonceOrPanic() []byte {
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		panic(err)
	}
	return nonce
}
