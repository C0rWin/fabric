package smartbft

import (
	"bytes"
	"encoding/hex"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/utils"
	"google.golang.org/grpc"
)

// BlocksStreamPuller fetches stream of blocks from active committee members
type BlocksStreamPuller struct {
	RetryTimeout time.Duration
	FetchTimeout time.Duration

	Endpoints []cluster.EndpointCriteria
	LastBlock *common.Block
	TLSCert   []byte
	Channel   string
	Signer    crypto.LocalSigner

	Logger *flogging.FabricLogger

	BlockVerifier BlockVerifier
	Dialer        cluster.Dialer
	Ledger        LedgerWriter
	StreamCreator StreamCreator

	endpointsLock        sync.RWMutex
	connectionLock       sync.RWMutex
	deliverEndpointIdx   int
	blockDeliverEndpoint cluster.EndpointCriteria
	conn                 *grpc.ClientConn
	stream               ImpatientStream
	stopFlag             int32
}

//go:generate mockery --name=AtomicBroadcastServer --case=underscore --output=mocks/
type AtomicBroadcastServer interface {
	orderer.AtomicBroadcastServer
}

//go:generate mockery --name=ImpatientStream --case=underscore --output=mocks/
type ImpatientStream interface {
	orderer.AtomicBroadcast_DeliverClient
	Abort()
}

//go:generate mockery --name=BlockVerifier --case=underscore --output=mocks/
type BlockVerifier interface {
	cluster.BlockVerifier
}

//go:generate mockery --name=LedgerWriter --case=underscore --output=mocks/
type LedgerWriter interface {
	cluster.LedgerWriter
}

type StreamCreator func(conn *grpc.ClientConn, timeout time.Duration) (ImpatientStream, error)

// NewImpatientStream creates an instance of the cluster impatient stream
func NewImpatientStream(conn *grpc.ClientConn, timeout time.Duration) (ImpatientStream, error) {
	streamCreator := cluster.NewImpatientStream(conn, timeout)
	return streamCreator()
}

func (p *BlocksStreamPuller) ContinuouslyPullBlocks() {
	for !p.isdone() {
		block, err := p.tryFetchBlocks()
		if err != nil {
			p.Logger.Errorf("Failed to pull next block, reason %s", err)
			time.Sleep(p.RetryTimeout)
			p.disconnect()
			continue
		}

		p.Logger.Debugf("Appending block (%d) to the ledger", block.Header.Number)
		if err := p.Ledger.Append(block); err != nil {
			p.Logger.Panicf("not able to append newly received block into the ledger, block number [%d], due to %s", block.Header.Number, err)
		}
		p.LastBlock = block
	}
}

// Stop halts blocks stream puller from fetching blocks
func (p *BlocksStreamPuller) Stop() {
	atomic.StoreInt32(&p.stopFlag, 1)
	p.disconnect()
}

func (p *BlocksStreamPuller) Initialize(endpoints []cluster.EndpointCriteria) {
	p.endpointsLock.Lock()
	defer p.endpointsLock.Unlock()
	p.Endpoints = endpoints
	if !p.disconnected() {
		p.Stop()
	}
}

// assignEndpoints assigns endpoints to decide where to fetch blocks from
func (p *BlocksStreamPuller) assignEndpoints() {
	p.endpointsLock.RLock()
	defer p.endpointsLock.RUnlock()
	p.deliverEndpointIdx = (p.deliverEndpointIdx + 1) % len(p.Endpoints)
	p.blockDeliverEndpoint = p.Endpoints[p.deliverEndpointIdx]
}

func (p *BlocksStreamPuller) tryFetchBlocks() (*common.Block, error) {
	if p.disconnected() {
		if err := p.obtainStream(); err != nil {
			p.Logger.Errorf("failed to obtain grpc stream to read blocks, because of %s", err)
			return nil, err
		}
		err := p.requestBlocks()
		if err != nil {
			p.Logger.Errorf("failed sending seek envelope, error %s, endpoint %s", err, p.blockDeliverEndpoint)
			return nil, err
		}
	}
	resp, err := p.stream.Recv()
	if err != nil {
		p.Logger.Errorf("Failed receiving next block from %s: %v", p.blockDeliverEndpoint, err)
		return nil, errors.Errorf("failed to receive next block, due to %s", err)
	}

	block, err := cluster.ExtractBlockFromResponse(resp)
	if err != nil {
		p.Logger.Errorf("Received a bad block from %s: %v", p.blockDeliverEndpoint, err)
		return nil, err
	}

	if p.LastBlock.Header.Number+1 != block.Header.Number {
		return nil, errors.Errorf("got unexpected sequence from %s - (%d) instead of (%d)", p.blockDeliverEndpoint, block.Header.Number, p.LastBlock.Header.Number+1)
	}
	if !bytes.Equal(block.Header.PreviousHash, p.LastBlock.Header.Hash()) {
		claimedPrevHash := hex.EncodeToString(block.Header.PreviousHash)
		actualPrevHash := hex.EncodeToString(p.LastBlock.Header.Hash())
		return nil,
			errors.Errorf("block [%d]'s hash (%s) mismatches %d's prev block hash (%s)",
				p.LastBlock.Header.Number, actualPrevHash, block.Header.Number, claimedPrevHash)
	}

	// sending nil for config envelope parameter, it will make use of the recent active configuration
	if err := cluster.VerifyBlockSignature(block, p.BlockVerifier, nil); err != nil {
		return nil, err
	}
	return block, nil
}

func (p *BlocksStreamPuller) isdone() bool {
	return atomic.LoadInt32(&p.stopFlag) == 1
}

// disconnect makes the BlockPuller close the connection and stream
// with the remote endpoint, and wipe the internal block buffer.
func (p *BlocksStreamPuller) disconnect() {
	p.connectionLock.Lock()
	defer p.connectionLock.Unlock()
	if p.stream != nil {
		p.stream.Abort()
	}

	if p.conn != nil {
		p.conn.Close()
	}
	p.conn = nil
}

func (p *BlocksStreamPuller) openStream() error {
	stream, err := p.StreamCreator(p.conn, p.FetchTimeout)
	if err != nil {
		p.Logger.Errorf("failed to create impatient delivery stream to fetch blocks from committee, error %s", err)
		return err
	}
	p.stream = stream
	return nil
}

func (p *BlocksStreamPuller) obtainStream() error {
	reConnected := false
	for p.disconnected() {
		reConnected = true
		// not connected, need to select next point and reconnect to it
		// to continue fetching blocks
		p.assignEndpoints()
		// make sure to get connected to committee OSN
		if err := p.connectToNextEndpoint(); err != nil {
			time.Sleep(p.RetryTimeout)
		}
	}

	if reConnected {
		err := p.openStream()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *BlocksStreamPuller) requestBlocks() error {
	if p.stream == nil {
		return errors.Errorf("grps stream is not initialized, cannot pull blocks from committee")
	}
	env, err := utils.CreateSignedEnvelopeWithTLSBinding(
		common.HeaderType_DELIVER_SEEK_INFO,
		p.Channel,
		p.Signer,
		&orderer.SeekInfo{
			Start:         &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: p.LastBlock.Header.Number + 1}}},
			Stop:          &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: math.MaxUint64}}},
			Behavior:      orderer.SeekInfo_BLOCK_UNTIL_READY,
			ErrorResponse: orderer.SeekInfo_BEST_EFFORT,
		},
		int32(0),
		uint64(0),
		util.ComputeSHA256(p.TLSCert),
	)
	if err != nil {
		p.Logger.Errorf("failed to create seek envelope to start fetching blocks, endpoint %s", err, p.blockDeliverEndpoint)
		return err
	}
	// sending request to pull blocks
	p.Logger.Debugf("sending request to pull blocks from committee, endpoint is [%s]", p.blockDeliverEndpoint)
	return p.stream.Send(env)
}

func (p *BlocksStreamPuller) connectToNextEndpoint() error {
	var err error
	p.connectionLock.Lock()
	defer p.connectionLock.Unlock()
	p.conn, err = p.Dialer.Dial(p.blockDeliverEndpoint)
	if err != nil {
		p.Logger.Warningf("Failed connecting to %s: %v", p.blockDeliverEndpoint, err)
		return err
	}
	return nil
}

// disconnected check whenever puller got already connected
func (p *BlocksStreamPuller) disconnected() bool {
	p.connectionLock.RLock()
	defer p.connectionLock.RUnlock()

	return p.conn == nil
}
