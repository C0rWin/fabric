package bft

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	gossipcommon "github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/internal/pkg/peer/blocksprovider/fake"
	"github.com/hyperledger/fabric/internal/pkg/peer/orderers"
	"github.com/hyperledger/fabric/protoutil"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var _ = Describe("BFT Blocksprovider", func() {
	var (
		d                           *Deliverer
		ccs                         []*grpc.ClientConn
		fakeDialer                  *fake.Dialer
		fakeGossipServiceAdapter    *fake.GossipServiceAdapter
		fakeOrdererConnectionSource *fake.OrdererConnectionSource
		fakeLedgerInfo              *fake.LedgerInfo
		fakeBlockHeaderVerifier     *fake.BlockHeaderVerifier
		fakeSigner                  *fake.Signer
		fakeDeliverStreamer         *fake.DeliverStreamer
		fakeDeliverClient           *fake.DeliverClient
		fakeSleeper                 *fake.Sleeper
		doneC                       chan struct{}
		recvStep                    chan struct{}
		endC                        chan struct{}
		mutex                       sync.Mutex
	)

	BeforeEach(func() {
		doneC = make(chan struct{})
		recvStep = make(chan struct{})

		// appease the race detector
		recvStep := recvStep
		doneC := doneC

		fakeDialer = &fake.Dialer{}
		ccs = nil
		fakeDialer.DialStub = func(target string, certPool *x509.CertPool) (*grpc.ClientConn, error) {
			mutex.Lock()
			defer mutex.Unlock()
			cc, err := grpc.Dial(target, grpc.WithInsecure())
			ccs = append(ccs, cc)
			Expect(err).NotTo(HaveOccurred())
			Expect(cc.GetState()).NotTo(Equal(connectivity.Shutdown))
			return cc, nil
		}

		fakeGossipServiceAdapter = &fake.GossipServiceAdapter{}
		fakeBlockHeaderVerifier = &fake.BlockHeaderVerifier{}
		fakeSigner = &fake.Signer{}

		fakeLedgerInfo = &fake.LedgerInfo{}
		fakeLedgerInfo.LedgerHeightReturns(7, nil)

		fakeOrdererConnectionSource = &fake.OrdererConnectionSource{}
		fakeOrdererConnectionSource.AllEndpointsReturns([]*orderers.Endpoint{{
			Address: "orderer-address",
		}}, nil)

		fakeDeliverClient = &fake.DeliverClient{}
		fakeDeliverClient.RecvStub = func() (*orderer.DeliverResponse, error) {
			select {
			case <-recvStep:
				return nil, fmt.Errorf("fake-recv-step-error")
			case <-doneC:
				return nil, nil
			}
		}

		fakeDeliverClient.CloseSendStub = func() error {
			select {
			case recvStep <- struct{}{}:
			case <-doneC:
			}
			return nil
		}

		fakeDeliverStreamer = &fake.DeliverStreamer{}
		fakeDeliverStreamer.DeliverReturns(fakeDeliverClient, nil)

		d = NewDeliverer(
			"channel-id",
			fakeGossipServiceAdapter,
			fakeLedgerInfo,
			fakeBlockHeaderVerifier,
			fakeDialer,
			fakeOrdererConnectionSource,
			doneC,
			fakeSigner,
			fakeDeliverStreamer,
			flogging.MustGetLogger("peer.bftblocksprovider").With("channel", "channel-id"),
			false,
			10*time.Second,
			100*time.Millisecond,
			time.Hour,
			1*time.Second,
		)
		d.TLSCertHash = []byte("tls-cert-hash")

		fakeSleeper = &fake.Sleeper{}
		d.sleeper.sleep = fakeSleeper.Sleep
	})

	JustBeforeEach(func() {
		endC = make(chan struct{})
		go func() {
			d.DeliverBlocks()
			close(endC)
		}()
	})

	AfterEach(func() {
		d.Stop() //close(doneC)
		<-endC
	})

	It("waits patiently for new blocks from the orderer", func() {
		Consistently(endC).ShouldNot(BeClosed())
		mutex.Lock()
		defer mutex.Unlock()
		Expect(ccs[0].GetState()).NotTo(Equal(connectivity.Shutdown))
	})

	It("checks the ledger height", func() {
		Eventually(fakeLedgerInfo.LedgerHeightCallCount).Should(Equal(2))
	})

	When("the ledger returns an error", func() {
		BeforeEach(func() {
			fakeLedgerInfo.LedgerHeightReturns(0, fmt.Errorf("fake-ledger-error"))
		})

		It("exits the loop", func() {
			Eventually(endC).Should(BeClosed())
		})
	})

	It("signs the seek info request", func() {
		Eventually(fakeSigner.SignCallCount).Should(Equal(1))
		// Note, the signer is used inside a util method
		// which has its own set of tests, so checking the args
		// in this test is unnecessary
	})

	When("the signer returns an error", func() {
		BeforeEach(func() {
			fakeSigner.SignReturns(nil, fmt.Errorf("fake-signer-error"))
		})

		It("exits the loop", func() {
			Eventually(endC).Should(BeClosed())
		})
	})

	It("gets all endpoints from the orderer connection source", func() {
		Eventually(fakeOrdererConnectionSource.AllEndpointsCallCount).Should(Equal(1))
	})

	When("the orderer connection source returns an error", func() {
		BeforeEach(func() {
			fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(0, nil, fmt.Errorf("fake-endpoint-error"))
			fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(1, []*orderers.Endpoint{
				{
					Address: "orderer-address",
				}}, nil)
		})

		It("sleeps and retries until a valid endpoint is selected", func() {
			Eventually(fakeOrdererConnectionSource.AllEndpointsCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
		})
	})

	When("the orderer connect is refreshed", func() {
		BeforeEach(func() {
			refreshedC := make(chan struct{})
			close(refreshedC)
			fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(0, []*orderers.Endpoint{
				{
					Address:   "orderer-address",
					Refreshed: refreshedC,
				}}, nil)
			fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(1, []*orderers.Endpoint{
				{
					Address: "orderer-address",
				}}, nil)
		})

		It("does not sleep, but disconnects and immediately tries to reconnect", func() {
			Eventually(fakeOrdererConnectionSource.AllEndpointsCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(0))
		})
	})

	It("dials the endpoint", func() {
		Eventually(fakeDialer.DialCallCount).Should(Equal(1))
		addr, tlsCerts := fakeDialer.DialArgsForCall(0)
		Expect(addr).To(Equal("orderer-address"))
		Expect(tlsCerts).To(BeNil()) // TODO
	})

	When("the dialer returns an error", func() {
		BeforeEach(func() {
			fakeDialer.DialReturnsOnCall(0, nil, fmt.Errorf("fake-dial-error"))
			cc, err := grpc.Dial("", grpc.WithInsecure())
			Expect(err).NotTo(HaveOccurred())
			fakeDialer.DialReturnsOnCall(1, cc, nil)
		})

		It("sleeps and retries until dial is successful", func() {
			Eventually(fakeDialer.DialCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
		})
	})

	It("constructs a deliver client", func() {
		Eventually(fakeDeliverStreamer.DeliverCallCount).Should(Equal(1))
	})

	When("the deliver client cannot be created", func() {
		BeforeEach(func() {
			fakeDeliverStreamer.DeliverReturnsOnCall(0, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(1, fakeDeliverClient, nil)
		})

		It("closes the grpc connection, sleeps, and tries again", func() {
			Eventually(fakeDeliverStreamer.DeliverCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
		})
	})

	When("there are consecutive errors", func() {
		BeforeEach(func() {
			fakeDeliverStreamer.DeliverReturnsOnCall(0, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(1, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(2, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(3, fakeDeliverClient, nil)
		})

		It("sleeps in an exponential fashion and retries until dial is successful", func() {
			Eventually(fakeDeliverStreamer.DeliverCallCount).Should(Equal(4))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(3))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(1)).To(Equal(120 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(2)).To(Equal(144 * time.Millisecond))
		})
	})

	When("the consecutive errors are unbounded and the peer is not a static leader", func() {
		BeforeEach(func() {
			fakeDeliverStreamer.DeliverReturns(nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(500, fakeDeliverClient, nil)
		})

		It("hits the maximum sleep time value in an exponential fashion and retries until exceeding the max retry duration", func() {
			d.YieldLeadership = true
			Eventually(fakeSleeper.SleepCallCount).Should(Equal(380))
			Expect(fakeSleeper.SleepArgsForCall(25)).To(Equal(9539 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(26)).To(Equal(10 * time.Second))
			Expect(fakeSleeper.SleepArgsForCall(27)).To(Equal(10 * time.Second))
			Expect(fakeSleeper.SleepArgsForCall(379)).To(Equal(10 * time.Second))
		})
	})

	When("the consecutive errors are unbounded and the peer is static leader", func() {
		BeforeEach(func() {
			fakeDeliverStreamer.DeliverReturns(nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(500, fakeDeliverClient, nil)
		})

		It("hits the maximum sleep time value in an exponential fashion and retries indefinitely", func() {
			d.YieldLeadership = false
			Eventually(fakeSleeper.SleepCallCount, 10*time.Second).Should(Equal(500))
			Expect(fakeSleeper.SleepArgsForCall(25)).To(Equal(9539 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(26)).To(Equal(10 * time.Second))
			Expect(fakeSleeper.SleepArgsForCall(27)).To(Equal(10 * time.Second))
			Expect(fakeSleeper.SleepArgsForCall(379)).To(Equal(10 * time.Second))
		})
	})

	When("an error occurs, then a block is successfully delivered", func() {
		BeforeEach(func() {
			fakeDeliverStreamer.DeliverReturnsOnCall(0, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(1, fakeDeliverClient, nil)
			fakeDeliverStreamer.DeliverReturnsOnCall(1, nil, fmt.Errorf("deliver-error"))
			fakeDeliverStreamer.DeliverReturnsOnCall(2, nil, fmt.Errorf("deliver-error"))
		})

		It("sleeps in an exponential fashion and retries until dial is successful", func() {
			Eventually(fakeDeliverStreamer.DeliverCallCount).Should(Equal(4))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(3))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(1)).To(Equal(120 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(2)).To(Equal(144 * time.Millisecond))
		})
	})

	It("sends a request to the deliver client for new blocks", func() {
		Eventually(fakeDeliverClient.SendCallCount).Should(Equal(1))
		mutex.Lock()
		defer mutex.Unlock()
		Expect(len(ccs)).To(Equal(1))
	})

	When("the send fails", func() {
		BeforeEach(func() {
			fakeDeliverClient.SendReturnsOnCall(0, fmt.Errorf("fake-send-error"))
			fakeDeliverClient.SendReturnsOnCall(1, nil)
			fakeDeliverClient.CloseSendStub = nil
		})

		It("disconnects, sleeps and retries until the send is successful", func() {
			Eventually(fakeDeliverClient.SendCallCount).Should(Equal(2))
			Expect(fakeDeliverClient.CloseSendCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
			mutex.Lock()
			defer mutex.Unlock()
			Expect(len(ccs)).To(Equal(2))
			Eventually(ccs[0].GetState).Should(Equal(connectivity.Shutdown))
		})
	})

	It("attempts to read blocks from the deliver stream", func() {
		Eventually(fakeDeliverClient.RecvCallCount).Should(Equal(1))
	})

	When("reading blocks from the deliver stream fails", func() {
		BeforeEach(func() {
			// appease the race detector
			doneC := doneC
			recvStep := recvStep
			fakeDeliverClient := fakeDeliverClient

			fakeDeliverClient.CloseSendStub = nil
			fakeDeliverClient.RecvStub = func() (*orderer.DeliverResponse, error) {
				if fakeDeliverClient.RecvCallCount() == 1 {
					return nil, fmt.Errorf("fake-recv-error")
				}
				select {
				case <-recvStep:
					return nil, fmt.Errorf("fake-recv-step-error")
				case <-doneC:
					return nil, nil
				}
			}
		})

		It("disconnects, sleeps, and retries until the recv is successful", func() {
			Eventually(fakeDeliverClient.RecvCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(1))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
		})
	})

	When("reading blocks from the deliver stream fails and then recovers", func() {
		BeforeEach(func() {
			// appease the race detector
			doneC := doneC
			recvStep := recvStep
			fakeDeliverClient := fakeDeliverClient

			fakeDeliverClient.CloseSendStub = func() error {
				if fakeDeliverClient.CloseSendCallCount() >= 5 {
					select {
					case <-doneC:
					case recvStep <- struct{}{}:
					}
				}
				return nil
			}
			fakeDeliverClient.RecvStub = func() (*orderer.DeliverResponse, error) {
				switch fakeDeliverClient.RecvCallCount() {
				case 1, 2, 4:
					return nil, fmt.Errorf("fake-recv-error")
				case 3:
					return &orderer.DeliverResponse{
						Type: &orderer.DeliverResponse_Block{
							Block: &common.Block{
								Header: &common.BlockHeader{
									Number: 8,
								},
							},
						},
					}, nil
				default:
					select {
					case <-recvStep:
						return nil, fmt.Errorf("fake-recv-step-error")
					case <-doneC:
						return nil, nil
					}
				}
			}
		})

		It("disconnects, sleeps, and retries until the recv is successful and resets the failure count", func() {
			Eventually(fakeDeliverClient.RecvCallCount).Should(Equal(5))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(3))
			Expect(fakeSleeper.SleepArgsForCall(0)).To(Equal(100 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(1)).To(Equal(120 * time.Millisecond))
			Expect(fakeSleeper.SleepArgsForCall(2)).To(Equal(100 * time.Millisecond))
		})
	})

	When("the deliver client returns a block", func() {
		BeforeEach(func() {
			// appease the race detector
			doneC := doneC
			recvStep := recvStep
			fakeDeliverClient := fakeDeliverClient

			fakeDeliverClient.RecvStub = func() (*orderer.DeliverResponse, error) {
				if fakeDeliverClient.RecvCallCount() == 1 {
					return &orderer.DeliverResponse{
						Type: &orderer.DeliverResponse_Block{
							Block: &common.Block{
								Header: &common.BlockHeader{
									Number: 8,
								},
							},
						},
					}, nil
				}
				select {
				case <-recvStep:
					return nil, fmt.Errorf("fake-recv-step-error")
				case <-doneC:
					return nil, nil
				}
			}
		})

		It("receives the block and loops, not sleeping", func() {
			Eventually(fakeDeliverClient.RecvCallCount).Should(Equal(2))
			Expect(fakeSleeper.SleepCallCount()).To(Equal(0))
		})

		It("checks the validity of the block", func() {
			Eventually(fakeBlockHeaderVerifier.VerifyBlockCallCount).Should(Equal(1))
			channelID, blockNum, block := fakeBlockHeaderVerifier.VerifyBlockArgsForCall(0)
			Expect(channelID).To(Equal(gossipcommon.ChannelID("channel-id")))
			Expect(blockNum).To(Equal(uint64(8)))
			Expect(proto.Equal(block, &common.Block{
				Header: &common.BlockHeader{
					Number: 8,
				},
			})).To(BeTrue())
		})

		When("the block is invalid", func() {
			BeforeEach(func() {
				fakeBlockHeaderVerifier.VerifyBlockReturns(fmt.Errorf("fake-verify-error"))
			})

			It("disconnects, sleeps, and tries again", func() {
				Eventually(fakeSleeper.SleepCallCount).Should(Equal(1))
				Expect(fakeDeliverClient.CloseSendCallCount()).To(Equal(1))
				mutex.Lock()
				defer mutex.Unlock()
				Expect(len(ccs)).To(Equal(2))
			})
		})

		It("adds the payload to gossip", func() {
			Eventually(fakeGossipServiceAdapter.AddPayloadCallCount).Should(Equal(1))
			channelID, payload := fakeGossipServiceAdapter.AddPayloadArgsForCall(0)
			Expect(channelID).To(Equal("channel-id"))
			Expect(payload).To(Equal(&gossip.Payload{
				Data: protoutil.MarshalOrPanic(&common.Block{
					Header: &common.BlockHeader{
						Number: 8,
					},
				}),
				SeqNum: 8,
			}))
		})

		When("adding the payload fails", func() {
			BeforeEach(func() {
				fakeGossipServiceAdapter.AddPayloadReturns(fmt.Errorf("payload-error"))
			})

			It("disconnects, sleeps, and tries again", func() {
				Eventually(fakeSleeper.SleepCallCount).Should(Equal(1))
				Expect(fakeDeliverClient.CloseSendCallCount()).To(Equal(1))
				mutex.Lock()
				defer mutex.Unlock()
				Expect(len(ccs)).To(Equal(2))
			})
		})

		It("gossips the block to the other peers", func() {
			Eventually(fakeGossipServiceAdapter.GossipCallCount).Should(Equal(1))
			msg := fakeGossipServiceAdapter.GossipArgsForCall(0)
			Expect(msg).To(Equal(&gossip.GossipMessage{
				Nonce:   0,
				Tag:     gossip.GossipMessage_CHAN_AND_ORG,
				Channel: []byte("channel-id"),
				Content: &gossip.GossipMessage_DataMsg{
					DataMsg: &gossip.DataMessage{
						Payload: &gossip.Payload{
							Data: protoutil.MarshalOrPanic(&common.Block{
								Header: &common.BlockHeader{
									Number: 8,
								},
							}),
							SeqNum: 8,
						},
					},
				},
			}))
		})
	})

	When("the deliver client returns a status", func() {
		var (
			status common.Status
		)

		BeforeEach(func() {
			// appease the race detector
			doneC := doneC
			recvStep := recvStep
			fakeDeliverClient := fakeDeliverClient

			status = common.Status_SUCCESS
			fakeDeliverClient.RecvStub = func() (*orderer.DeliverResponse, error) {
				if fakeDeliverClient.RecvCallCount() == 1 {
					return &orderer.DeliverResponse{
						Type: &orderer.DeliverResponse_Status{
							Status: status,
						},
					}, nil
				}
				select {
				case <-recvStep:
					return nil, fmt.Errorf("fake-recv-step-error")
				case <-doneC:
					return nil, nil
				}
			}
		})

		It("disconnects with an error, and sleeps because the block request is infinite and should never complete", func() {
			Eventually(fakeSleeper.SleepCallCount).Should(Equal(1))
		})

		When("the status is not successful", func() {
			BeforeEach(func() {
				status = common.Status_FORBIDDEN
			})

			It("still disconnects with an error", func() {
				Eventually(fakeSleeper.SleepCallCount).Should(Equal(1))
			})
		})
	})

	When("there are several orderers", func() {
		var blocksChannels map[string]chan *orderer.DeliverResponse
		var eventuallyTimeout = 3 * time.Second
		var endpoints []*orderers.Endpoint

		BeforeEach(func() {
			// appease the race detector
			fakeOrdererConnectionSource := fakeOrdererConnectionSource
			doneC := doneC

			endpoints = []*orderers.Endpoint{
				{Address: "orderer1-address"},
				{Address: "orderer2-address"},
				{Address: "orderer3-address"},
				{Address: "orderer4-address"},
			}

			fakeOrdererConnectionSource.AllEndpointsReturns(endpoints, nil)

			fakeDeliverClients := make(map[string]*fake.DeliverClient)
			blocksChannels = make(map[string]chan *orderer.DeliverResponse)
			recvSteps := make(map[string]chan struct{})
			for _, endpoint := range endpoints {
				fakeDeliverClients[endpoint.Address] = new(fake.DeliverClient)
				blocksChannels[endpoint.Address] = make(chan *orderer.DeliverResponse)
				recvSteps[endpoint.Address] = make(chan struct{})
			}

			// appease the race detector
			blocksChannels := blocksChannels

			fakeDeliverClients["orderer1-address"].RecvStub = func() (*orderer.DeliverResponse, error) {
				return recvStub(fakeDeliverClients["orderer1-address"], blocksChannels["orderer1-address"], recvSteps["orderer1-address"], doneC)
			}
			fakeDeliverClients["orderer1-address"].CloseSendStub = func() error {
				return closeStub(recvSteps["orderer1-address"], doneC)
			}

			fakeDeliverClients["orderer2-address"].RecvStub = func() (*orderer.DeliverResponse, error) {
				return recvStub(fakeDeliverClients["orderer2-address"], blocksChannels["orderer2-address"], recvSteps["orderer2-address"], doneC)
			}
			fakeDeliverClients["orderer2-address"].CloseSendStub = func() error {
				return closeStub(recvSteps["orderer2-address"], doneC)
			}

			fakeDeliverClients["orderer3-address"].RecvStub = func() (*orderer.DeliverResponse, error) {
				return recvStub(fakeDeliverClients["orderer3-address"], blocksChannels["orderer3-address"], recvSteps["orderer3-address"], doneC)
			}
			fakeDeliverClients["orderer3-address"].CloseSendStub = func() error {
				return closeStub(recvSteps["orderer3-address"], doneC)
			}

			fakeDeliverClients["orderer4-address"].RecvStub = func() (*orderer.DeliverResponse, error) {
				return recvStub(fakeDeliverClients["orderer4-address"], blocksChannels["orderer4-address"], recvSteps["orderer4-address"], doneC)
			}
			fakeDeliverClients["orderer4-address"].CloseSendStub = func() error {
				return closeStub(recvSteps["orderer4-address"], doneC)
			}

			fakeDeliverStreamer.DeliverStub = func(ctx context.Context, clientConn *grpc.ClientConn) (orderer.AtomicBroadcast_DeliverClient, error) {
				return fakeDeliverClients[clientConn.Target()], nil
			}
		})

		It("starts blocks and headers deliverers", func() {
			Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer1-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer2-address", "orderer3-address", "orderer4-address"}))
		})

		It("receives blocks and headers", func() {
			Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer1-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer2-address", "orderer3-address", "orderer4-address"}))

			for i := 8; i < 13; i++ {
				for _, blocksChannel := range blocksChannels {
					Expect(sendDeliverResponse(blocksChannel, block(i), 3*time.Second)).To(BeTrue())
				}
			}

			Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(12))
			for _, endpointAddress := range []string{"orderer2-address", "orderer3-address", "orderer4-address"} {
				Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(12))
			}
		})

		It("can handle block censorship by orderer", func() {
			Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer1-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer2-address", "orderer3-address", "orderer4-address"}))

			for _, blocksChannel := range blocksChannels {
				Expect(sendDeliverResponse(blocksChannel, block(8), 3*time.Second)).To(BeTrue())
			}

			Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(8))
			for _, endpointAddress := range []string{"orderer2-address", "orderer3-address", "orderer4-address"} {
				Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(8))
			}

			for address, blocksChannel := range blocksChannels {
				if address != "orderer1-address" {
					Expect(sendDeliverResponse(blocksChannel, block(9), 3*time.Second)).To(BeTrue())
				}
			}

			Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer2-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer1-address", "orderer3-address", "orderer4-address"}))

			for address, blocksChannel := range blocksChannels {
				if address != "orderer1-address" {
					Expect(sendDeliverResponse(blocksChannel, block(10), 3*time.Second)).To(BeTrue())
				}
			}

			Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(10))
			for _, endpointAddress := range []string{"orderer1-address", "orderer3-address", "orderer4-address"} {
				if endpointAddress == "orderer1-address" {
					_, err := LastHeaderNum(d, endpointAddress)()
					Expect(err).To(HaveOccurred())
				} else {
					Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(10))
				}
			}
		})

		It("can handle failure of blocks deliverer and switch to another orderer", func() {
			Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer1-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer2-address", "orderer3-address", "orderer4-address"}))

			for _, blocksChannel := range blocksChannels {
				Expect(sendDeliverResponse(blocksChannel, block(8), 3*time.Second)).To(BeTrue())
			}

			Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(8))
			for _, endpointAddress := range []string{"orderer2-address", "orderer3-address", "orderer4-address"} {
				Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(8))
			}

			for address, blocksChannel := range blocksChannels {
				if address != "orderer1-address" {
					Expect(sendDeliverResponse(blocksChannel, block(9), 3*time.Second)).To(BeTrue())
				} else {
					Expect(sendDeliverResponse(blocksChannel, status(common.Status_INTERNAL_SERVER_ERROR), 3*time.Second)).To(BeTrue())
				}
			}

			Eventually(BlocksDelivererAddress(d), 10*eventuallyTimeout).Should(Equal("orderer2-address"))
			Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer1-address", "orderer3-address", "orderer4-address"}))

			for _, blocksChannel := range blocksChannels {
				Expect(sendDeliverResponse(blocksChannel, block(10), 3*time.Second)).To(BeTrue())
			}

			Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(10))
			for _, endpointAddress := range []string{"orderer1-address", "orderer3-address", "orderer4-address"} {
				Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(10))
			}
		})

		When("the orderer connect is refreshed", func() {
			var refreshed chan struct{}

			BeforeEach(func() {
				// appease the race detector
				fakeOrdererConnectionSource := fakeOrdererConnectionSource

				refreshed = make(chan struct{})
				endpointsWithRefreshed := []*orderers.Endpoint{
					{Address: "orderer1-address", Refreshed: refreshed},
					{Address: "orderer2-address", Refreshed: refreshed},
					{Address: "orderer3-address", Refreshed: refreshed},
					{Address: "orderer4-address", Refreshed: refreshed},
				}

				fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(0, endpointsWithRefreshed, nil)
				fakeOrdererConnectionSource.AllEndpointsReturnsOnCall(1, endpoints, nil)
			})

			It("does not sleep, but disconnects and immediately tries to reconnect", func() {
				Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer1-address"))
				Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer2-address", "orderer3-address", "orderer4-address"}))

				for _, blocksChannel := range blocksChannels {
					Expect(sendDeliverResponse(blocksChannel, block(8), 3*time.Second)).To(BeTrue())
				}

				Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(8))
				for _, endpointAddress := range []string{"orderer2-address", "orderer3-address", "orderer4-address"} {
					Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(8))
				}

				close(refreshed)

				Eventually(BlocksDelivererAddress(d), eventuallyTimeout).Should(Equal("orderer2-address"))
				Eventually(HeadersDeliverersAddresses(d), eventuallyTimeout).Should(ConsistOf([]string{"orderer1-address", "orderer3-address", "orderer4-address"}))

				Eventually(fakeOrdererConnectionSource.AllEndpointsCallCount).Should(Equal(2))
				Expect(fakeSleeper.SleepCallCount()).To(Equal(0))

				for _, blocksChannel := range blocksChannels {
					Expect(sendDeliverResponse(blocksChannel, block(9), 3*time.Second)).To(BeTrue())
				}

				Eventually(LastBlockNum(d), eventuallyTimeout).Should(Equal(9))
				for _, endpointAddress := range []string{"orderer1-address", "orderer3-address", "orderer4-address"} {
					Eventually(LastHeaderNum(d, endpointAddress), eventuallyTimeout).Should(Equal(9))
				}
			})
		})
	})
})

func HeadersDeliverersAddresses(d *Deliverer) func() ([]string, error) {
	return func() (headersDeliverersAddresses []string, err error) {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		if d.headersDeliverers == nil {
			err = errors.New("headersDeliverers is nil")
			return
		}
		for key := range d.headersDeliverers {
			headersDeliverersAddresses = append(headersDeliverersAddresses, key)
		}
		return
	}
}

func BlocksDelivererAddress(d *Deliverer) func() (string, error) {
	return func() (string, error) {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		if d.blocksDeliverer == nil {
			return "", errors.New("blocksDeliverer is nil")
		}
		return d.blocksDeliverer.Endpoint.Address, nil
	}
}

func LastBlockNum(d *Deliverer) func() (int, error) {
	return func() (int, error) {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		blockNum, _, err := d.blocksDeliverer.LastBlockNum()
		if err != nil {
			return 0, err
		}
		return int(blockNum), nil
	}
}

func LastHeaderNum(d *Deliverer, endpointAddress string) func() (int, error) {
	return func() (int, error) {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		for _, headersDeliverer := range d.headersDeliverers {
			if headersDeliverer.Endpoint.Address == endpointAddress {
				blockNum, _, err := headersDeliverer.LastBlockNum()
				if err != nil {
					return 0, err
				}
				return int(blockNum), nil
			}
		}
		return 0, errors.Errorf("cannot find headers deliverer with endpoint address: %s", endpointAddress)
	}
}

func recvStub(fakeDeliverClient *fake.DeliverClient, recv chan *orderer.DeliverResponse, recvStep chan struct{}, doneC chan struct{}) (*orderer.DeliverResponse, error) {
	select {
	case block := <-recv:
		return block, nil
	case <-recvStep:
		return nil, fmt.Errorf("fake-recv-step-error")
	case <-doneC:
		return nil, nil
	}
}

func closeStub(recvStep chan struct{}, doneC chan struct{}) error {
	select {
	case recvStep <- struct{}{}:
	case <-doneC:
	}
	return nil
}

func block(num int) *orderer.DeliverResponse {
	return &orderer.DeliverResponse{
		Type: &orderer.DeliverResponse_Block{
			Block: &common.Block{
				Header: &common.BlockHeader{
					Number: uint64(num),
				},
			},
		},
	}
}

func status(status common.Status) *orderer.DeliverResponse {
	return &orderer.DeliverResponse{
		Type: &orderer.DeliverResponse_Status{
			Status: status,
		},
	}
}

func sendDeliverResponse(c chan *orderer.DeliverResponse, response *orderer.DeliverResponse, timeout time.Duration) bool {
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(timeout)
		timeoutChannel <- true
	}()

	select {
	case c <- response:
		return true
	case <-timeoutChannel:
		return false
	}
}
