/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft_test

import (
	"testing"

	"github.com/SmartBFT-Go/consensus/protos"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/mocks"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestEgressBroadcastConsensus(t *testing.T) {
	logger := flogging.MustGetLogger("test")
	rpc := &mocks.RPC{}
	rpc.On("SendConsensus", mock.Anything, mock.Anything).Return(nil)
	egress := &smartbft.Egress{
		Logger:  logger,
		Channel: "test",
		RPC:     rpc,
		Nodes:   []uint64{1, 2, 3},
	}

	prePrepare := &protos.Message{
		Content: &protos.Message_PrePrepare{
			PrePrepare: &protos.PrePrepare{View: 1, Seq: 1},
		},
	}

	expectedMsg := &orderer.ConsensusRequest{
		Payload: protoutil.MarshalOrPanic(prePrepare),
		Channel: "test",
	}

	egress.BroadcastConsensus(prePrepare)

	rpc.AssertCalled(t, "SendConsensus", uint64(1), expectedMsg)
	rpc.AssertCalled(t, "SendConsensus", uint64(2), expectedMsg)
	rpc.AssertCalled(t, "SendConsensus", uint64(3), expectedMsg)
	rpc.AssertNumberOfCalls(t, "SendConsensus", 3)
}

func TestEgressSendConsensus(t *testing.T) {
	logger := flogging.MustGetLogger("test")
	rpc := &mocks.RPC{}
	rpc.On("SendConsensus", mock.Anything, mock.Anything).Return(nil)
	egress := &smartbft.Egress{
		Logger:  logger,
		Channel: "test",
		RPC:     rpc,
	}

	viewData := &protos.Message{
		Content: &protos.Message_NewView{
			NewView: &protos.NewView{SignedViewData: []*protos.SignedViewData{
				{RawViewData: []byte{1, 2, 3}},
			}},
		},
	}

	egress.SendConsensus(42, viewData)

	rpc.AssertCalled(t, "SendConsensus", uint64(42), &orderer.ConsensusRequest{
		Payload: protoutil.MarshalOrPanic(viewData),
		Channel: "test",
	})
}

func TestEgressSendTransaction(t *testing.T) {
	logger := flogging.MustGetLogger("test")
	rpc := &mocks.RPC{}
	rpc.On("SendSubmit", mock.Anything, mock.Anything).Return(nil)
	egress := &smartbft.Egress{
		Logger:  logger,
		Channel: "test",
		RPC:     rpc,
	}

	t.Run("malformed transaction", func(t *testing.T) {
		badTransactionAttempt := func() {
			egress.SendTransaction(42, []byte{1, 2, 3})
		}
		expectedErr := "Failed unmarshaling request [1 2 3] to envelope: proto: common.Envelope: illegal tag 0 (wire type 1)"
		assert.PanicsWithValue(t, expectedErr, badTransactionAttempt)
	})

	t.Run("valid transaction", func(t *testing.T) {
		egress.SendTransaction(42, protoutil.MarshalOrPanic(&common.Envelope{
			Payload: []byte{1, 2, 3},
		}))
	})

	rpc.AssertCalled(t, "SendSubmit", uint64(42), &orderer.SubmitRequest{
		Channel: "test",
		Payload: &common.Envelope{
			Payload: []byte{1, 2, 3},
		},
	})
}
