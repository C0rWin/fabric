/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/utils"
)

//go:generate mockery -dir . -name SignerSerializer -case underscore -output ./mocks/

type SignerSerializer interface {
	crypto.LocalSigner
}

type Signer struct {
	ID               uint64
	SignerSerializer SignerSerializer
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
	block, err := ProposalToBlock(proposal)
	if err != nil {
		s.Logger.Panicf("Tried to sign bad proposal: %v", err)
	}
	sig := Signature{
		BlockHeader:     block.Header.Bytes(),
		SignatureHeader: utils.MarshalOrPanic(utils.NewSignatureHeaderOrPanic(s.SignerSerializer)),
		OrdererBlockMetadata: utils.MarshalOrPanic(&common.OrdererBlockMetadata{
			LastConfig:        &common.LastConfig{Index: uint64(proposal.VerificationSequence)},
			ConsenterMetadata: proposal.Metadata,
		}),
	}

	signature := utils.SignOrPanic(s.SignerSerializer, sig.AsBytes())
	return &types.Signature{
		Id:    s.ID,
		Value: signature,
		Msg:   sig.Marshal(),
	}
}
