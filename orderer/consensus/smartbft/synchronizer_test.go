/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft_test

import (
	"io/ioutil"
	"testing"

	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	mocks2 "github.com/hyperledger/fabric/orderer/consensus/mocks"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/mocks"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSynchronizerSync(t *testing.T) {
	blockBytes, err := ioutil.ReadFile("testdata/mychannel.block")
	require.NoError(t, err)

	goodConfigBlock := &common.Block{}
	require.NoError(t, proto.Unmarshal(blockBytes, goodConfigBlock))

	b99 := makeBlockWithMetadata(99, 42, &smartbftprotos.ViewMetadata{ViewId: 1, LatestSequence: 12})
	b100 := makeBlockWithMetadata(100, 42, &smartbftprotos.ViewMetadata{ViewId: 1, LatestSequence: 13})
	b101 := makeConfigBlockWithMetadata(goodConfigBlock, 101, &smartbftprotos.ViewMetadata{ViewId: 2, LatestSequence: 1})
	b102 := makeBlockWithMetadata(102, 101, &smartbftprotos.ViewMetadata{ViewId: 2, LatestSequence: 3})

	blockNum2configSqn := map[uint64]uint64{
		99:  7,
		100: 7,
		101: 8,
		102: 8,
	}

	t.Run("no remotes", func(t *testing.T) {
		bp := &mocks.FakeBlockPuller{}
		fakeCS := &mocks2.FakeConsenterSupport{}
		fakeCS.ChainIDReturns("mychannel")
		fakeCS.HeightReturns(100)
		fakeCS.BlockReturns(b99)
		fakeCS.SequenceReturns(blockNum2configSqn[99])

		syn, err := smartbft.NewSynchronizer(fakeCS, bp, 4, flogging.NewFabricLogger(zap.NewExample()))
		require.NoError(t, err)
		require.NotNil(t, syn)

		metadata, sqn := syn.Sync()
		assert.Equal(t, uint64(1), metadata.ViewId)
		assert.Equal(t, uint64(12), metadata.LatestSequence)
		assert.Equal(t, blockNum2configSqn[99], sqn)
	})

	t.Run("all nodes present", func(t *testing.T) {
		bp := &mocks.FakeBlockPuller{}
		bp.HeightsByEndpointsReturns(
			map[string]uint64{
				"example.com:1": 100,
				"example.com:2": 102,
				"example.com:3": 103,
				"example.com:4": 200, //byzantine, lying
			},
			nil,
		)
		bp.PullBlockReturnsOnCall(0, b100)
		bp.PullBlockReturnsOnCall(1, b101)
		bp.PullBlockReturnsOnCall(2, b102)

		height := uint64(100)
		ledger := map[uint64]*common.Block{99: b99}

		fakeCS := &mocks2.FakeConsenterSupport{}
		fakeCS.ChainIDReturns("mychannel")
		fakeCS.HeightCalls(func() uint64 { return height })
		fakeCS.SequenceCalls(func() uint64 { return blockNum2configSqn[height-1] })
		fakeCS.WriteConfigBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.WriteBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.BlockCalls(func(sqn uint64) *common.Block {
			return ledger[sqn]
		})

		syn, err := smartbft.NewSynchronizer(fakeCS, bp, 4, flogging.NewFabricLogger(zap.NewExample()))
		require.NoError(t, err)
		require.NotNil(t, syn)

		metadata, sqn := syn.Sync()
		assert.Equal(t, uint64(2), metadata.ViewId)
		assert.Equal(t, uint64(3), metadata.LatestSequence)
		assert.Equal(t, blockNum2configSqn[101], sqn)
	})

	t.Run("3/4 nodes present", func(t *testing.T) {
		bp := &mocks.FakeBlockPuller{}
		bp.HeightsByEndpointsReturns(
			map[string]uint64{
				"example.com:1": 100,
				"example.com:2": 102,
				"example.com:4": 200, //byzantine, lying
			},
			nil,
		)
		bp.PullBlockReturnsOnCall(0, b100)
		bp.PullBlockReturnsOnCall(1, b101)
		bp.PullBlockReturnsOnCall(2, b102)

		height := uint64(100)
		ledger := map[uint64]*common.Block{99: b99}

		fakeCS := &mocks2.FakeConsenterSupport{}
		fakeCS.ChainIDReturns("mychannel")
		fakeCS.HeightCalls(func() uint64 { return height })
		fakeCS.SequenceCalls(func() uint64 { return blockNum2configSqn[height-1] })
		fakeCS.WriteConfigBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.WriteBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.BlockCalls(func(sqn uint64) *common.Block {
			return ledger[sqn]
		})

		syn, err := smartbft.NewSynchronizer(fakeCS, bp, 4, flogging.NewFabricLogger(zap.NewExample()))
		require.NoError(t, err)
		require.NotNil(t, syn)

		metadata, sqn := syn.Sync()
		assert.Equal(t, uint64(2), metadata.ViewId)
		assert.Equal(t, uint64(1), metadata.LatestSequence)
		assert.Equal(t, blockNum2configSqn[101], sqn)
	})

	t.Run("2/4 nodes present", func(t *testing.T) {
		bp := &mocks.FakeBlockPuller{}
		bp.HeightsByEndpointsReturns(
			map[string]uint64{
				"example.com:1": 100,
				"example.com:4": 200, //byzantine, lying
			},
			nil,
		)
		bp.PullBlockReturnsOnCall(0, b100)
		bp.PullBlockReturnsOnCall(1, b101)
		bp.PullBlockReturnsOnCall(2, b102)

		height := uint64(100)
		ledger := map[uint64]*common.Block{99: b99}

		fakeCS := &mocks2.FakeConsenterSupport{}
		fakeCS.ChainIDReturns("mychannel")
		fakeCS.HeightCalls(func() uint64 { return height })
		fakeCS.SequenceCalls(func() uint64 { return blockNum2configSqn[height-1] })
		fakeCS.WriteConfigBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.WriteBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.BlockCalls(func(sqn uint64) *common.Block {
			return ledger[sqn]
		})

		syn, err := smartbft.NewSynchronizer(fakeCS, bp, 4, flogging.NewFabricLogger(zap.NewExample()))
		require.NoError(t, err)
		require.NotNil(t, syn)

		metadata, sqn := syn.Sync()
		assert.Equal(t, uint64(1), metadata.ViewId)
		assert.Equal(t, uint64(12), metadata.LatestSequence)
		assert.Equal(t, blockNum2configSqn[99], sqn)
	})

	t.Run("1/4 nodes present", func(t *testing.T) {
		bp := &mocks.FakeBlockPuller{}
		bp.HeightsByEndpointsReturns(
			map[string]uint64{
				"example.com:1": 100,
			},
			nil,
		)
		bp.PullBlockReturnsOnCall(0, b100)
		bp.PullBlockReturnsOnCall(1, b101)
		bp.PullBlockReturnsOnCall(2, b102)

		height := uint64(100)
		ledger := map[uint64]*common.Block{99: b99}

		fakeCS := &mocks2.FakeConsenterSupport{}
		fakeCS.ChainIDReturns("mychannel")
		fakeCS.HeightCalls(func() uint64 { return height })
		fakeCS.SequenceCalls(func() uint64 { return blockNum2configSqn[height-1] })
		fakeCS.WriteConfigBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.WriteBlockCalls(func(b *common.Block, m []byte) {
			ledger[height] = b
			height++
		})
		fakeCS.BlockCalls(func(sqn uint64) *common.Block {
			return ledger[sqn]
		})

		syn, err := smartbft.NewSynchronizer(fakeCS, bp, 4, flogging.NewFabricLogger(zap.NewExample()))
		require.NoError(t, err)
		require.NotNil(t, syn)

		metadata, sqn := syn.Sync()
		assert.Equal(t, uint64(1), metadata.ViewId)
		assert.Equal(t, uint64(12), metadata.LatestSequence)
		assert.Equal(t, blockNum2configSqn[99], sqn)
	})
}

func makeBlockWithMetadata(sqnNum, lastConfigIndex uint64, viewMetadata *smartbftprotos.ViewMetadata) *common.Block {
	block := protoutil.NewBlock(sqnNum, nil)
	block.Metadata.Metadata[common.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(
		&common.Metadata{
			Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: lastConfigIndex}),
		},
	)
	block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER] = protoutil.MarshalOrPanic(
		&common.Metadata{
			Value: protoutil.MarshalOrPanic(viewMetadata),
		},
	)
	return block
}

func makeConfigBlockWithMetadata(configBlock *common.Block, sqnNum uint64, viewMetadata *smartbftprotos.ViewMetadata) *common.Block {
	block := proto.Clone(configBlock).(*common.Block)
	block.Header.Number = sqnNum

	block.Metadata.Metadata[common.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(
		&common.Metadata{
			Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: sqnNum}),
		},
	)
	block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER] = protoutil.MarshalOrPanic(
		&common.Metadata{
			Value: protoutil.MarshalOrPanic(viewMetadata),
		},
	)
	return block
}
