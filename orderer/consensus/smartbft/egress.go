/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"github.com/SmartBFT-Go/consensus/protos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protoutil"
)

//go:generate mockery -dir . -name RPC -case underscore -output mocks

type RPC interface {
	SendConsensus(dest uint64, msg *orderer.ConsensusRequest) error
	SendSubmit(dest uint64, request *orderer.SubmitRequest) error
}

type PanicLogger interface {
	Panicf(template string, args ...interface{})
}

type Egress struct {
	Channel string
	Nodes   []uint64
	RPC     RPC
	Logger  PanicLogger
}

func (e *Egress) BroadcastConsensus(m *protos.Message) {
	for _, node := range e.Nodes {
		e.RPC.SendConsensus(node, bftMsgToClusterMsg(m, e.Channel))
	}
}

func (e *Egress) SendConsensus(targetID uint64, m *protos.Message) {
	e.RPC.SendConsensus(targetID, bftMsgToClusterMsg(m, e.Channel))
}

func (e *Egress) SendTransaction(targetID uint64, request []byte) {
	env := &common.Envelope{}
	err := proto.Unmarshal(request, env)
	if err != nil {
		e.Logger.Panicf("Failed unmarshaling request %v to envelope: %v", request, err)
	}
	msg := &orderer.SubmitRequest{
		Channel: e.Channel,
		Payload: env,
	}
	e.RPC.SendSubmit(targetID, msg)
}

func bftMsgToClusterMsg(message *protos.Message, channel string) *orderer.ConsensusRequest {
	return &orderer.ConsensusRequest{
		Payload: protoutil.MarshalOrPanic(message),
		Channel: channel,
	}
}
