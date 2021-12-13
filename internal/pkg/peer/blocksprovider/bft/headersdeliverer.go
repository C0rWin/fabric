/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bft

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/internal/pkg/peer/blocksprovider"
	"github.com/hyperledger/fabric/internal/pkg/peer/orderers"
	"github.com/hyperledger/fabric/protoutil"

	"github.com/pkg/errors"
)

type sleeper struct {
	sleep func(time.Duration)
}

func (s sleeper) Sleep(d time.Duration, doneC chan struct{}) {
	if s.sleep == nil {
		timer := time.NewTimer(d)
		select {
		case <-timer.C:
		case <-doneC:
			timer.Stop()
		}
		return
	}
	s.sleep(d)
}

type HeadersDeliverer struct {
	ChannelID       string
	Gossip          blocksprovider.GossipServiceAdapter
	Ledger          blocksprovider.LedgerInfo
	HeaderVerifier  blocksprovider.BlockHeaderVerifier
	Dialer          blocksprovider.Dialer
	Endpoint        *orderers.Endpoint
	DoneC           chan struct{}
	Signer          identity.SignerSerializer
	DeliverStreamer blocksprovider.DeliverStreamer
	Logger          *flogging.FabricLogger

	MaxRetryDelay     time.Duration
	InitialRetryDelay time.Duration

	// TLSCertHash should be nil when TLS is not enabled
	TLSCertHash []byte // util.ComputeSHA256(b.credSupport.GetClientCertificate().Certificate[0])

	sleeper sleeper

	started       bool
	mutex         sync.Mutex
	lastBlockNum  *uint64
	lastBlockTime time.Time
}

// DeliverHeaders used to pull out headers from the ordering service to
// distributed them across peers
func (d *HeadersDeliverer) DeliverHeaders() {
	d.setStarted()

	failureCounter := 0
	totalDuration := time.Duration(0)

	// InitialRetryDelay * backoffExponentBase^n > MaxRetryDelay
	// backoffExponentBase^n > MaxRetryDelay / InitialRetryDelay
	// n * log(backoffExponentBase) > log(MaxRetryDelay / InitialRetryDelay)
	// n > log(MaxRetryDelay / InitialRetryDelay) / log(backoffExponentBase)
	maxFailures := int(math.Log(float64(d.MaxRetryDelay)/float64(d.InitialRetryDelay)) / math.Log(backoffExponentBase))
	for {
		select {
		case <-d.DoneC:
			return
		default:
		}

		if failureCounter > 0 {
			var sleepDuration time.Duration
			if failureCounter-1 > maxFailures {
				sleepDuration = d.MaxRetryDelay
			} else {
				sleepDuration = time.Duration(math.Pow(1.2, float64(failureCounter-1))*100) * time.Millisecond
			}
			totalDuration += sleepDuration
			d.sleeper.Sleep(sleepDuration, d.DoneC)
		}

		ledgerHeight, err := d.Ledger.LedgerHeight()
		if err != nil {
			d.Logger.Error("Did not return ledger height, something is critically wrong", err)
			d.setStopped()
			return
		}

		seekInfoEnv, err := d.createSeekInfo(ledgerHeight)
		if err != nil {
			d.Logger.Error("Could not create a signed Deliver SeekInfo message, something is critically wrong", err)
			d.setStopped()
			return
		}

		deliverClient, cancel, err := d.connect(seekInfoEnv)
		if err != nil {
			d.Logger.Warningf("Could not connect to ordering service: %s", err)
			failureCounter++
			continue
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
			case response, ok := <-recv:
				if !ok {
					connLogger.Warningf("Orderer hung up without sending status")
					failureCounter++
					break RecvLoop
				}
				err = d.processMsg(response)
				if err != nil {
					connLogger.Warningf("Got error while attempting to receive headers: %v", err)
					failureCounter++
					break RecvLoop
				}
				failureCounter = 0
			case <-d.DoneC:
				break RecvLoop
			}
		}

		// cancel and wait for our spawned go routine to exit
		cancel()
		<-recv
	}
}

func (d *HeadersDeliverer) processMsg(msg *orderer.DeliverResponse) error {
	switch t := msg.Type.(type) {
	case *orderer.DeliverResponse_Status:
		if t.Status == common.Status_SUCCESS {
			return errors.Errorf("received success for a seek that should never complete")
		}

		return errors.Errorf("received bad status %v from orderer", t.Status)
	case *orderer.DeliverResponse_Block:
		blockNum := t.Block.Header.Number
		if err := d.HeaderVerifier.VerifyHeader(d.ChannelID, t.Block); err != nil {
			return errors.WithMessage(err, "header from orderer could not be verified")
		}

		d.mutex.Lock()
		d.lastBlockNum = &blockNum
		d.lastBlockTime = time.Now()
		d.mutex.Unlock()
		d.Logger.Infof("Received block with num: %v from endpoint: %v", blockNum, d.Endpoint.Address)
		return nil
	default:
		d.Logger.Warningf("Received unknown: %v", t)
		return errors.Errorf("unknown message type '%T'", msg.Type)
	}
}

// Stop stops blocks delivery provider
func (d *HeadersDeliverer) Stop() {
	// this select is not race-safe, but it prevents a panic
	// for careless callers multiply invoking stop
	select {
	case <-d.DoneC:
	default:
		close(d.DoneC)
		d.setStopped()
	}
}

func (d *HeadersDeliverer) connect(seekInfoEnv *common.Envelope) (orderer.AtomicBroadcast_DeliverClient, func(), error) {
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

func (d *HeadersDeliverer) createSeekInfo(ledgerHeight uint64) (*common.Envelope, error) {
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
			Behavior:    orderer.SeekInfo_BLOCK_UNTIL_READY,
			ContentType: orderer.SeekInfo_HEADER_WITH_SIG,
		},
		int32(0),
		uint64(0),
		d.TLSCertHash,
	)
}

func (d *HeadersDeliverer) LastBlockNum() (uint64, time.Time, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.lastBlockNum == nil {
		return 0, time.Unix(0, 0), errors.New("Not found")
	}
	return *d.lastBlockNum, d.lastBlockTime, nil
}

func (d *HeadersDeliverer) isStarted() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.started
}

func (d *HeadersDeliverer) setStarted() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.started = true
}

func (d *HeadersDeliverer) setStopped() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.started = false
}
