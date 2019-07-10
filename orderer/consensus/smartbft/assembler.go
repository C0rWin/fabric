/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/asn1"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

//go:generate mockery -dir . -name Ledger -case underscore -output mocks

type Ledger interface {
	// Height returns the number of blocks in the ledger this channel is associated with.
	Height() uint64

	// Block returns a block with the given number,
	// or nil if such a block doesn't exist.
	Block(number uint64) *common.Block
}

type Assembler struct {
	Ledger Ledger
	Logger *flogging.FabricLogger
}

func (a *Assembler) AssembleProposal(metadata []byte, requests [][]byte) (nextProp types.Proposal, remainder [][]byte) {
	if len(requests) == 0 {
		a.Logger.Panicf("Programming error, no requests in proposal")
	}
	batchedRequests := singleConfigTxOrSeveralNonConfigTx(requests, a.Logger)

	lastConfigBlock := lastConfigBlockFromLedgerOrPanic(a.Ledger, a.Logger)
	lastBlock := lastBlockFromLedgerOrPanic(a.Ledger, a.Logger)

	block := protoutil.NewBlock(lastBlock.Header.Number+1, protoutil.BlockHeaderHash(lastBlock.Header))
	block.Data = &common.BlockData{Data: batchedRequests}
	block.Header.DataHash = protoutil.BlockDataHash(block.Data)
	block.Metadata.Metadata[common.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&common.Metadata{
		Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: lastConfigBlock.Header.Number}),
	})

	block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER] = metadata

	tuple := &ByteBufferTuple{
		A: protoutil.MarshalOrPanic(block.Data),
		B: protoutil.MarshalOrPanic(block.Metadata),
	}
	prop := types.Proposal{
		Header:               protoutil.MarshalOrPanic(block.Header),
		Payload:              tuple.ToBytes(),
		Metadata:             metadata,
		VerificationSequence: int64(lastConfigBlock.Header.Number),
	}

	return prop, requests[len(batchedRequests):]
}

func singleConfigTxOrSeveralNonConfigTx(requests [][]byte, logger PanicLogger) [][]byte {
	// Scan until a config transaction is found
	var batchedRequests [][]byte
	var i int
	for i < len(requests) {
		currentRequest := requests[i]
		envelope, err := protoutil.UnmarshalEnvelope(currentRequest)
		if err != nil {
			logger.Panicf("Programming error, received bad envelope but should have validated it: %v", err)
			continue
		}

		// If we saw a config transaction, we cannot add any more transactions to the batch.
		if protoutil.IsConfigTransaction(envelope) {
			break
		}

		// Else, it's not a config transaction, so add it to the batch.
		batchedRequests = append(batchedRequests, currentRequest)
		i++
	}

	// If we don't have any transaction in the batch, it is safe to assume we only
	// saw a single transaction which is a config transaction.
	if len(batchedRequests) == 0 {
		batchedRequests = [][]byte{requests[0]}
	}

	// At this point, batchedRequests contains either a single config transaction, or a few non config transactions.
	return batchedRequests
}

func lastConfigBlockFromLedgerOrPanic(ledger Ledger, logger PanicLogger) *common.Block {
	block, err := lastConfigBlockFromLedger(ledger)
	if err != nil {
		logger.Panicf("Failed retrieving last config block: %v", err)
	}
	return block
}

func lastConfigBlockFromLedger(ledger Ledger) (*common.Block, error) {
	lastBlockSeq := ledger.Height() - 1
	lastBlock := ledger.Block(lastBlockSeq)
	if lastBlock == nil {
		return nil, errors.Errorf("unable to retrieve block [%d]", lastBlockSeq)
	}
	lastConfigBlock, err := cluster.LastConfigBlock(lastBlock, ledger)
	if err != nil {
		return nil, err
	}
	return lastConfigBlock, nil
}

func lastBlockFromLedgerOrPanic(ledger Ledger, logger PanicLogger) *common.Block {
	lastBlockSeq := ledger.Height() - 1
	lastBlock := ledger.Block(lastBlockSeq)
	if lastBlock == nil {
		logger.Panicf("Failed retrieving last block")
	}
	return lastBlock
}

type ByteBufferTuple struct {
	A []byte
	B []byte
}

func (bbt *ByteBufferTuple) ToBytes() []byte {
	bytes, err := asn1.Marshal(*bbt)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (bbt *ByteBufferTuple) FromBytes(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, bbt)
	return err
}
