/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft_test

import (
	"errors"
	"testing"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/mocks"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSigner(t *testing.T) {
	ss := &mocks.SignerSerializer{}
	s := &smartbft.Signer{
		SignerSerializer: ss,
		Logger:           flogging.MustGetLogger("test"),
		ID:               3,
	}

	t.Run("signing fails", func(t *testing.T) {
		ss.On("Sign", mock.Anything).Return(nil, errors.New("foo")).Once()
		assert.PanicsWithValue(t, "Failed signing message: foo", func() {
			s.Sign(nil)
		})
	})

	t.Run("signing succeeds", func(t *testing.T) {
		ss.On("Sign", mock.Anything).Return([]byte{1, 2, 3}, nil).Once()
		assert.Equal(t, []byte{1, 2, 3}, s.Sign(nil))
	})
}

func TestSignProposal(t *testing.T) {
	ss := &mocks.SignerSerializer{}
	ss.On("Sign", mock.Anything).Return([]byte{1, 2, 3}, nil).Once()
	ss.On("NewSignatureHeader", mock.Anything).Return(&common.SignatureHeader{
		Creator: []byte{0, 2, 4, 6},
	}, nil)

	s := &smartbft.Signer{
		SignerSerializer: ss,
		Logger:           flogging.MustGetLogger("test"),
		ID:               3,
	}

	lastBlock := makeNonConfigBlock(19, 10)
	lastConfigBlock := makeConfigBlock(10)
	ledger := &mocks.Ledger{}
	ledger.On("Height").Return(uint64(20))
	ledger.On("Block", uint64(19)).Return(lastBlock)
	ledger.On("Block", uint64(10)).Return(lastConfigBlock)

	assembler := &smartbft.Assembler{
		Logger: flogging.MustGetLogger("test"),
		Ledger: ledger,
	}

	env := utils.MarshalOrPanic(&common.Envelope{Payload: []byte{1, 2, 3, 4, 5}})
	prop, _ := assembler.AssembleProposal(nil, [][]byte{env})

	sig := s.SignProposal(prop)
	assert.NotNil(t, sig)

	signature := smartbft.Signature{}
	signature.Unmarshal(sig.Msg)

	assert.Equal(t, s.ID, sig.Id)
	assert.Equal(t, []byte{1, 2, 3}, sig.Value)
	assert.Equal(t, prop.Header, signature.BlockHeader)
	sigHdr := &common.SignatureHeader{}
	assert.NoError(t, proto.Unmarshal(signature.SignatureHeader, sigHdr))
	assert.Equal(t, []byte{0, 2, 4, 6}, sigHdr.Creator)
	assert.Equal(t, signature.OrdererBlockMetadata, utils.MarshalOrPanic(&common.OrdererBlockMetadata{
		LastConfig:        &common.LastConfig{Index: uint64(prop.VerificationSequence)},
		ConsenterMetadata: prop.Metadata,
	}))
}

func TestSignBadProposal(t *testing.T) {
	ss := &mocks.SignerSerializer{}
	ss.On("Sign", mock.Anything).Return([]byte{1, 2, 3}, nil).Once()
	ss.On("Serialize", mock.Anything).Return([]byte{0, 2, 4, 6}, nil)

	s := &smartbft.Signer{
		SignerSerializer: ss,
		Logger:           flogging.MustGetLogger("test"),
		ID:               3,
	}

	f := func() {
		s.SignProposal(types.Proposal{})
	}
	assert.PanicsWithValue(t, "Tried to sign bad proposal: proposal header cannot be nil", f)

}
