package smartbft_test

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric/orderer/consensus/smartbft"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/mocks/crypto"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/mocks"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

type testDialer struct {
}

func (t *testDialer) Dial(endpointCriteria cluster.EndpointCriteria) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()

	return grpc.DialContext(ctx, endpointCriteria.Endpoint, grpc.WithBlock(), grpc.WithInsecure())
}

func TestBlocksStreamPuller_ContinuouslyPullBlocks(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer lis.Close()

	srv, err := comm.NewGRPCServerFromListener(lis, comm.ServerConfig{})
	assert.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(10)

	channelID := "test_channel"
	signerID := uint64(1)
	signerIdentity := []byte{1, 2, 3, 4}
	var signature []byte
	var tlsCert []byte

	lastBlock := common.NewBlock(1, nil)
	blockResponses := prepareBlocks(lastBlock, []*common.MetadataSignature{
		{
			SignerId:  signerID,
			Signature: signature,
		},
	}, 11)

	blockVerifier := &mocks.BlockVerifier{}
	blockVerifier.On("Id2Identity", mock.Anything).Return(map[uint64][]byte{
		signerID: signerIdentity,
	})

	signer := &crypto.LocalSigner{}

	blockVerifier.On("VerifyBlockSignature", mock.Anything, mock.Anything).Run(
		func(args mock.Arguments) {
			signatureSet, ok := args.Get(0).([]*common.SignedData)
			assert.True(t, ok)
			assert.NotNil(t, signatureSet)
			assert.Len(t, signatureSet, 1)
			signedData := signatureSet[0]
			assert.NotNil(t, signedData)
			assert.Equal(t, signerIdentity, signedData.Identity)
		}).Return(nil)

	ledger := &mocks.LedgerWriter{}

	broadcastServer := &mocks.AtomicBroadcastServer{}
	broadcastServer.On("Deliver", mock.Anything).Run(func(args mock.Arguments) {
		stream := args.Get(0).(orderer.AtomicBroadcast_DeliverServer)
		actualEnv, err := stream.Recv()
		assert.NoError(t, err)

		expectedEnv, err := utils.CreateSignedEnvelopeWithTLSBinding(
			common.HeaderType_DELIVER_SEEK_INFO,
			channelID,
			signer,
			&orderer.SeekInfo{
				Start:         &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: 2}}},
				Stop:          &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: math.MaxUint64}}},
				Behavior:      orderer.SeekInfo_BLOCK_UNTIL_READY,
				ErrorResponse: orderer.SeekInfo_BEST_EFFORT,
			},
			int32(0),
			uint64(0),
			util.ComputeSHA256(tlsCert),
		)
		assert.NoError(t, err)
		assert.True(t, proto.Equal(expectedEnv, actualEnv))

		for _, blockResponse := range blockResponses {
			stream.Send(&orderer.DeliverResponse{
				Type: &orderer.DeliverResponse_Block{
					Block: blockResponse,
				},
			})
		}
	}).Return(nil)

	orderer.RegisterAtomicBroadcastServer(srv.Server(), broadcastServer)
	go srv.Start()
	defer srv.Stop()

	_, port, err := net.SplitHostPort(lis.Addr().String())
	assert.NoError(t, err)

	puller := &smartbft.BlocksStreamPuller{
		RetryTimeout:  time.Millisecond,
		FetchTimeout:  5 * time.Second,
		Ledger:        ledger,
		Dialer:        &testDialer{},
		BlockVerifier: blockVerifier,
		Signer:        signer,
		StreamCreator: smartbft.NewImpatientStream,
		LastBlock:     lastBlock,
		Logger:        flogging.MustGetLogger("test"),
		Channel:       channelID,
		TLSCert:       tlsCert,
		Endpoints: []cluster.EndpointCriteria{
			{
				Endpoint:   fmt.Sprintf("127.0.0.1:%s", port),
				TLSRootCAs: [][]byte{},
			},
		},
	}

	blockSeq := 0
	ledger.On("Append", mock.Anything).Run(func(args mock.Arguments) {
		defer wg.Done()
		block := args.Get(0).(*common.Block)
		assert.True(t, proto.Equal(blockResponses[blockSeq], block))
		blockSeq++
	}).Return(nil)

	go puller.ContinuouslyPullBlocks()
	wg.Wait()
	puller.Stop()
}

func prepareBlocks(lastBlock *common.Block, signatures []*common.MetadataSignature, lastIndex uint64) []*common.Block {
	var blocks []*common.Block

	for prevBlock, i := lastBlock, lastBlock.Header.Number+1; i <= lastIndex; i++ {
		block := common.NewBlock(i, prevBlock.Header.Hash())
		block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = utils.MarshalOrPanic(&common.Metadata{
			Signatures: signatures,
			Value: utils.MarshalOrPanic(&common.OrdererBlockMetadata{
				LastConfig: &common.LastConfig{
					Index: 1,
				},
			}),
		})

		prevBlock = block
		blocks = append(blocks, block)
	}

	return blocks
}
