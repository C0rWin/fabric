/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
)

type Signer struct {
	ID               uint64
	SignerSerializer identity.SignerSerializer
	Logger           PanicLogger
}

func (s *Signer) Sign(msg []byte) []byte {
	signature, err := s.SignerSerializer.Sign(msg)
	if err != nil {
		s.Logger.Panicf("Failed signing message: %v", err)
	}
	return signature
}

func (s *Signer) SignProposal(proposal types.Proposal) *types.Signature {
	block := &common.Block{}
	// TODO: check errors...
	proto.Unmarshal(proposal.Header, block.Header)
	proto.Unmarshal(proposal.Payload, block.Data)
	proto.Unmarshal(proposal.Metadata, block.Metadata)

	sig := Signature{
		BlockHeader:       block.Header,
		SignatureHeader:   protoutil.NewSignatureHeaderOrPanic(s.SignerSerializer),
		ConsenterMetadata: block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER],
		LastConfigSeq:     proposal.VerificationSequence,
	}

	signature := protoutil.SignOrPanic(s.SignerSerializer, sig.AsBytes(s.SignerSerializer))
	return &types.Signature{
		Id:    s.ID,
		Value: signature,
		Msg:   sig.Marshal(),
	}
}
