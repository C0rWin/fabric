package bft

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	gossipcommon "github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/internal/pkg/peer/blocksprovider"
	"github.com/hyperledger/fabric/internal/pkg/peer/orderers"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// Deliverer the actual implementation for BlocksProvider interface
type BlocksDeliverer struct {
	ChannelID       string
	Gossip          blocksprovider.GossipServiceAdapter
	Ledger          blocksprovider.LedgerInfo
	BlockVerifier   blocksprovider.BlockHeaderVerifier
	Dialer          blocksprovider.Dialer
	Endpoint        *orderers.Endpoint
	DoneC           chan struct{}
	Signer          identity.SignerSerializer
	DeliverStreamer blocksprovider.DeliverStreamer
	Logger          *flogging.FabricLogger

	// TLSCertHash should be nil when TLS is not enabled
	TLSCertHash []byte // util.ComputeSHA256(b.credSupport.GetClientCertificate().Certificate[0])

	mutex         sync.Mutex
	lastBlockNum  *uint64
	lastBlockTime time.Time
}

const backoffExponentBase = 1.2

// DeliverBlocks used to pull out blocks from the ordering service to
// distributed them across peers
func (d *BlocksDeliverer) DeliverBlocks(failureCounter *int) (criticalError bool, endpointRefreshed bool) {
	ledgerHeight, err := d.Ledger.LedgerHeight()
	if err != nil {
		d.Logger.Error("Did not return ledger height, something is critically wrong", err)
		criticalError = true
		return
	}

	seekInfoEnv, err := d.createSeekInfo(ledgerHeight)
	if err != nil {
		d.Logger.Error("Could not create a signed Deliver SeekInfo message, something is critically wrong", err)
		criticalError = true
		return
	}

	deliverClient, cancel, err := d.connect(seekInfoEnv)
	if err != nil {
		d.Logger.Warningf("Could not connect to ordering service: %s", err)
		(*failureCounter)++
		return
	}

	connLogger := d.Logger.With("orderer-address", d.Endpoint.Address)

	recv := make(chan *orderer.DeliverResponse)
	go func() {
		for {
			resp, err := deliverClient.Recv()
			if err != nil {
				connLogger.Warningf("Encountered an error reading from deliver stream: %s", err)
				close(recv)
				return
			}
			select {
			case recv <- resp:
			case <-d.DoneC:
				close(recv)
				return
			}
		}
	}()

RecvLoop: // Loop until the endpoint is refreshed, or there is an error on the connection
	for {
		select {
		case <-d.Endpoint.Refreshed:
			connLogger.Infof("Ordering endpoints have been refreshed, disconnecting from deliver to reconnect using updated endpoints")
			endpointRefreshed = true
			break RecvLoop
		case response, ok := <-recv:
			if !ok {
				connLogger.Warningf("Orderer hung up without sending status")
				(*failureCounter)++
				break RecvLoop
			}
			err = d.processMsg(response)
			if err != nil {
				connLogger.Warningf("Got error while attempting to receive blocks: %v", err)
				(*failureCounter)++
				break RecvLoop
			}
			*failureCounter = 0
		case <-d.DoneC:
			break RecvLoop
		}
	}

	// cancel and wait for our spawned go routine to exit
	cancel()
	<-recv
	return
}

func (d *BlocksDeliverer) processMsg(msg *orderer.DeliverResponse) error {
	switch t := msg.Type.(type) {
	case *orderer.DeliverResponse_Status:
		if t.Status == common.Status_SUCCESS {
			return errors.Errorf("received success for a seek that should never complete")
		}

		return errors.Errorf("received bad status %v from orderer", t.Status)
	case *orderer.DeliverResponse_Block:
		blockNum := t.Block.Header.Number
		if err := d.BlockVerifier.VerifyBlock(gossipcommon.ChannelID(d.ChannelID), blockNum, t.Block); err != nil {
			return errors.WithMessage(err, "block from orderer could not be verified")
		}

		d.mutex.Lock()
		d.lastBlockNum = &blockNum
		d.lastBlockTime = time.Now()
		d.mutex.Unlock()
		d.Logger.Infof("Received block with num: %v", blockNum)

		marshaledBlock, err := proto.Marshal(t.Block)
		if err != nil {
			return errors.WithMessage(err, "block from orderer could not be re-marshaled")
		}

		// Create payload with a block received
		payload := &gossip.Payload{
			Data:   marshaledBlock,
			SeqNum: blockNum,
		}

		// Use payload to create gossip message
		gossipMsg := &gossip.GossipMessage{
			Nonce:   0,
			Tag:     gossip.GossipMessage_CHAN_AND_ORG,
			Channel: []byte(d.ChannelID),
			Content: &gossip.GossipMessage_DataMsg{
				DataMsg: &gossip.DataMessage{
					Payload: payload,
				},
			},
		}

		d.Logger.Debugf("Adding payload to local buffer, blockNum = [%d]", blockNum)
		// Add payload to local state payloads buffer
		if err := d.Gossip.AddPayload(d.ChannelID, payload); err != nil {
			d.Logger.Warningf("Block [%d] received from ordering service wasn't added to payload buffer: %v", blockNum, err)
			return errors.WithMessage(err, "could not add block as payload")
		}

		// Gossip messages with other nodes
		d.Logger.Debugf("Gossiping block [%d]", blockNum)
		d.Gossip.Gossip(gossipMsg)
		return nil
	default:
		d.Logger.Warningf("Received unknown: %v", t)
		return errors.Errorf("unknown message type '%T'", msg.Type)
	}
}

// Stop stops blocks delivery provider
func (d *BlocksDeliverer) Stop() {
	// this select is not race-safe, but it prevents a panic
	// for careless callers multiply invoking stop
	select {
	case <-d.DoneC:
	default:
		close(d.DoneC)
	}
}

func (d *BlocksDeliverer) connect(seekInfoEnv *common.Envelope) (orderer.AtomicBroadcast_DeliverClient, func(), error) {
	conn, err := d.Dialer.Dial(d.Endpoint.Address, d.Endpoint.CertPool)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "could not dial endpoint '%s'", d.Endpoint.Address)
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	deliverClient, err := d.DeliverStreamer.Deliver(ctx, conn)
	if err != nil {
		conn.Close()
		ctxCancel()
		return nil, nil, errors.WithMessagef(err, "could not create deliver client to endpoints '%s'", d.Endpoint.Address)
	}

	err = deliverClient.Send(seekInfoEnv)
	if err != nil {
		deliverClient.CloseSend()
		conn.Close()
		ctxCancel()
		return nil, nil, errors.WithMessagef(err, "could not send deliver seek info handshake to '%s'", d.Endpoint.Address)
	}

	return deliverClient, func() {
		deliverClient.CloseSend()
		ctxCancel()
		conn.Close()
	}, nil
}

func (d *BlocksDeliverer) createSeekInfo(ledgerHeight uint64) (*common.Envelope, error) {
	return protoutil.CreateSignedEnvelopeWithTLSBinding(
		common.HeaderType_DELIVER_SEEK_INFO,
		d.ChannelID,
		d.Signer,
		&orderer.SeekInfo{
			Start: &orderer.SeekPosition{
				Type: &orderer.SeekPosition_Specified{
					Specified: &orderer.SeekSpecified{
						Number: ledgerHeight,
					},
				},
			},
			Stop: &orderer.SeekPosition{
				Type: &orderer.SeekPosition_Specified{
					Specified: &orderer.SeekSpecified{
						Number: math.MaxUint64,
					},
				},
			},
			Behavior: orderer.SeekInfo_BLOCK_UNTIL_READY,
		},
		int32(0),
		uint64(0),
		d.TLSCertHash,
	)
}

func (d *BlocksDeliverer) LastBlockNum() (uint64, time.Time, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.lastBlockNum == nil {
		return 0, time.Unix(0, 0), errors.New("Not found")
	}
	return *d.lastBlockNum, d.lastBlockTime, nil
}
