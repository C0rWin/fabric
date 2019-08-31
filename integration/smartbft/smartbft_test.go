/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package smartbft

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	"github.com/hyperledger/fabric/protoutil"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var _ = Describe("EndToEnd Smart BFT configuration test", func() {
	var (
		testDir string
		client  *docker.Client
		network *nwo.Network

		networkProcess   ifrit.Process
		ordererProcesses []ifrit.Process
		peerProcesses    ifrit.Process
	)

	BeforeEach(func() {
		networkProcess = nil
		ordererProcesses = nil
		peerProcesses = nil
		var err error
		testDir, err = ioutil.TempDir("", "e2e-smartbft-test")
		Expect(err).NotTo(HaveOccurred())

		client, err = docker.NewClientFromEnv()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if networkProcess != nil {
			networkProcess.Signal(syscall.SIGTERM)
			Eventually(networkProcess.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if peerProcesses != nil {
			peerProcesses.Signal(syscall.SIGTERM)
			Eventually(peerProcesses.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if network != nil {
			network.Cleanup()
		}
		for _, ordererInstance := range ordererProcesses {
			ordererInstance.Signal(syscall.SIGTERM)
			Eventually(ordererInstance.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		os.RemoveAll(testDir)
	})

	Describe("smartbft network", func() {
		It("smartbft multiple nodes stop start all nodes", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			ordererRunner := network.NetworkGroupRunner()
			networkProcess = ifrit.Invoke(ordererRunner)

			peer := network.Peer("Org1", "peer0")

			Eventually(networkProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

			assertBlockReception(map[string]int{"systemchannel": 0}, network.Orderers, peer, network)

			channel := "testchannel1"

			orderer := network.Orderers[rand.Intn(len(network.Orderers))]
			fmt.Fprintf(GinkgoWriter, "Picking orderer %s to create channel", orderer.Name)
			network.CreateAndJoinChannel(orderer, channel)

			nwo.DeployChaincode(network, channel, orderer, nwo.Chaincode{
				Name:    "mycc",
				Version: "0.0",
				Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
				Ctor:    `{"Args":["init","a","100","b","200"]}`,
				Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
			})

			By("querying the chaincode")

			sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
				ChannelID: channel,
				Name:      "mycc",
				Ctor:      `{"Args":["query","a"]}`,
			})
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
			Expect(sess).To(gbytes.Say("100"))

			orderer = network.Orderers[rand.Intn(len(network.Orderers))]
			fmt.Fprintf(GinkgoWriter, "Picking orderer %s to send invoke", orderer.Name)
			invokeQuery(network, peer, orderer, channel, 90)

			By("Taking down all the nodes")
			networkProcess.Signal(syscall.SIGTERM)
			Eventually(networkProcess.Wait(), network.EventuallyTimeout).Should(Receive())

			By("Bringing up all the nodes")
			ordererRunner = network.NetworkGroupRunner()
			networkProcess = ifrit.Invoke(ordererRunner)
			Eventually(networkProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

			orderer = network.Orderers[rand.Intn(len(network.Orderers))]
			fmt.Fprintf(GinkgoWriter, "Picking orderer %s to invoke", orderer.Name)
			invokeQuery(network, peer, orderer, channel, 80)
		})

		It("smartbft assisted synchronization", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			var ordererRunners []*ginkgomon.Runner
			for _, orderer := range network.Orderers {
				runner := network.OrdererRunner(orderer)
				runner.Command.Env = append(runner.Command.Env, "FABRIC_LOGGING_SPEC=orderer.consensus.smartbft=debug:grpc=debug")
				ordererRunners = append(ordererRunners, runner)
				proc := ifrit.Invoke(runner)
				ordererProcesses = append(ordererProcesses, proc)
				Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			}

			peerRunner := network.PeerGroupRunner()
			peerProcesses = ifrit.Invoke(peerRunner)

			Eventually(peerProcesses.Ready(), network.EventuallyTimeout).Should(BeClosed())

			peer := network.Peer("Org1", "peer0")

			assertBlockReception(map[string]int{"systemchannel": 0}, network.Orderers, peer, network)

			By("Waiting for followers to see the leader")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			channel := "testchannel1"

			orderer := network.Orderers[0]
			network.CreateAndJoinChannel(orderer, channel)

			assertBlockReception(map[string]int{"systemchannel": 1}, network.Orderers, peer, network)

			nwo.DeployChaincode(network, channel, network.Orderers[0], nwo.Chaincode{
				Name:    "mycc",
				Version: "0.0",
				Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
				Ctor:    `{"Args":["init","a","100","b","200"]}`,
				Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
			})

			assertBlockReception(map[string]int{"testchannel1": 1}, network.Orderers, peer, network)

			By("Taking down a follower node")
			ordererProcesses[3].Signal(syscall.SIGTERM)
			Eventually(ordererProcesses[3].Wait(), network.EventuallyTimeout).Should(Receive())

			invokeQuery(network, peer, orderer, channel, 90)
			invokeQuery(network, peer, orderer, channel, 80)
			invokeQuery(network, peer, orderer, channel, 70)
			invokeQuery(network, peer, orderer, channel, 60)

			By("Bringing up the follower node")
			runner := network.OrdererRunner(network.Orderers[3])
			runner.Command.Env = append(runner.Command.Env, "FABRIC_LOGGING_SPEC=orderer.consensus.smartbft=debug:grpc=debug")
			proc := ifrit.Invoke(runner)
			ordererProcesses[3] = proc
			Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Starting view with number 0 and sequence 2"))

			By("Waiting communication to be established from the leader")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			invokeQuery(network, peer, orderer, channel, 50)
			time.Sleep(time.Second * 2)
			invokeQuery(network, peer, orderer, channel, 40)
			time.Sleep(time.Second * 2)
			invokeQuery(network, peer, orderer, channel, 30)
			time.Sleep(time.Second * 2)
			invokeQuery(network, peer, orderer, channel, 20)
			time.Sleep(time.Second * 2)

			assertBlockReception(map[string]int{"testchannel1": 9}, network.Orderers, peer, network)

			invokeQuery(network, peer, orderer, channel, 10)
			assertBlockReception(map[string]int{"testchannel1": 10}, network.Orderers, peer, network)

			invokeQuery(network, peer, orderer, channel, 0)
			assertBlockReception(map[string]int{"testchannel1": 11}, network.Orderers, peer, network)

			By("Ensuring follower participates in consensus")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Deciding on seq 11"))
		})

		It("smartbft autonomous synchronization", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()
			network.EventuallyTimeout = time.Minute * 2

			var ordererRunners []*ginkgomon.Runner
			for _, orderer := range network.Orderers {
				runner := network.OrdererRunner(orderer)
				runner.Command.Env = append(runner.Command.Env, "FABRIC_LOGGING_SPEC=orderer.consensus.smartbft=debug:grpc=debug")
				ordererRunners = append(ordererRunners, runner)
				proc := ifrit.Invoke(runner)
				ordererProcesses = append(ordererProcesses, proc)
				Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			}

			peerRunner := network.PeerGroupRunner()
			peerProcesses = ifrit.Invoke(peerRunner)

			Eventually(peerProcesses.Ready(), network.EventuallyTimeout).Should(BeClosed())

			peer := network.Peer("Org1", "peer0")

			assertBlockReception(map[string]int{"systemchannel": 0}, network.Orderers, peer, network)

			By("Waiting for followers to see the leader")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			channel := "testchannel1"

			orderer := network.Orderers[0]
			network.CreateAndJoinChannel(orderer, channel)

			assertBlockReception(map[string]int{"systemchannel": 1}, network.Orderers, peer, network)

			nwo.DeployChaincode(network, channel, network.Orderers[0], nwo.Chaincode{
				Name:    "mycc",
				Version: "0.0",
				Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
				Ctor:    `{"Args":["init","a","100","b","200"]}`,
				Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
			})

			assertBlockReception(map[string]int{"testchannel1": 1}, network.Orderers, peer, network)

			By("Taking down a follower node")
			ordererProcesses[3].Signal(syscall.SIGTERM)
			Eventually(ordererProcesses[3].Wait(), network.EventuallyTimeout).Should(Receive())

			invokeQuery(network, peer, orderer, channel, 90)
			invokeQuery(network, peer, orderer, channel, 80)
			invokeQuery(network, peer, orderer, channel, 70)
			invokeQuery(network, peer, orderer, channel, 60)

			By("Bringing up the follower node")
			runner := network.OrdererRunner(network.Orderers[3])
			runner.Command.Env = append(runner.Command.Env, "FABRIC_LOGGING_SPEC=orderer.consensus.smartbft=debug:grpc=debug")
			proc := ifrit.Invoke(runner)
			ordererProcesses[3] = proc
			Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Starting view with number 0 and sequence 2"))

			By("Waiting communication to be established from the leader")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			By("Waiting for follower to understand it is behind")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Leader's sequence is 5 and ours is 2"))

			By("Waiting for follower to synchronize itself")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Finished synchronizing with cluster"))

			By("Waiting for all nodes to have the latest block sequence")
			assertBlockReception(map[string]int{"testchannel1": 5}, network.Orderers, peer, network)

			By("Ensuring the follower is functioning properly")
			invokeQuery(network, peer, orderer, channel, 50)
			assertBlockReception(map[string]int{"testchannel1": 6}, network.Orderers, peer, network)
		})

		It("smartbft node addition", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			var ordererRunners []*ginkgomon.Runner
			for _, orderer := range network.Orderers {
				runner := network.OrdererRunner(orderer)
				ordererRunners = append(ordererRunners, runner)
				proc := ifrit.Invoke(runner)
				ordererProcesses = append(ordererProcesses, proc)
				Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			}

			peerRunner := network.PeerGroupRunner()
			peerProcesses = ifrit.Invoke(peerRunner)

			Eventually(peerProcesses.Ready(), network.EventuallyTimeout).Should(BeClosed())

			peer := network.Peer("Org1", "peer0")

			assertBlockReception(map[string]int{"systemchannel": 0}, network.Orderers, peer, network)

			By("Waiting for followers to see the leader")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			channel := "testchannel1"

			orderer := network.Orderers[0]
			network.CreateAndJoinChannel(orderer, channel)

			assertBlockReception(map[string]int{"systemchannel": 1}, network.Orderers, peer, network)

			nwo.DeployChaincode(network, channel, network.Orderers[0], nwo.Chaincode{
				Name:    "mycc",
				Version: "0.0",
				Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
				Ctor:    `{"Args":["init","a","100","b","200"]}`,
				Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
			})

			assertBlockReception(map[string]int{"testchannel1": 1}, network.Orderers, peer, network)

			By("Adding a new consenter")

			orderer5 := &nwo.Orderer{
				Name:         "orderer5",
				Organization: "OrdererOrg",
			}
			network.Orderers = append(network.Orderers, orderer5)

			ports := nwo.Ports{}
			for _, portName := range nwo.OrdererPortNames() {
				ports[portName] = network.ReservePort()
			}
			network.PortsByOrdererID[orderer5.ID()] = ports

			network.GenerateCryptoConfig()
			network.GenerateOrdererConfig(orderer5)

			sess, err := network.Cryptogen(commands.Extend{
				Config: network.CryptoConfigPath(),
				Input:  network.CryptoPath(),
			})
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))

			ordererCertificatePath := filepath.Join(network.OrdererLocalTLSDir(orderer5), "server.crt")
			ordererCertificate, err := ioutil.ReadFile(ordererCertificatePath)
			Expect(err).NotTo(HaveOccurred())

			ordererIdentity, err := ioutil.ReadFile(network.OrdererCert(orderer5))
			Expect(err).NotTo(HaveOccurred())

			for _, channel := range []string{"systemchannel", "testchannel1"} {
				nwo.UpdateSmartBFTMetadata(network, peer, orderer, channel, func(md *smartbft.ConfigMetadata) {
					md.Consenters = append(md.Consenters, &smartbft.Consenter{
						MspId:       "OrdererMSP",
						ConsenterId: 4,
						Identity: protoutil.MarshalOrPanic(&msp.SerializedIdentity{
							Mspid:   "OrdererMSP",
							IdBytes: ordererIdentity,
						}),
						ServerTlsCert: ordererCertificate,
						ClientTlsCert: ordererCertificate,
						Host:          "127.0.0.1",
						Port:          uint32(network.OrdererPort(orderer5, nwo.ListenPort)),
					})
				})

				assertBlockReception(map[string]int{channel: 2}, network.Orderers[:4], peer, network)
			}

			restart := func() {
				for i, orderer := range network.Orderers[:4] {
					By(fmt.Sprintf("Killing %s", orderer.Name))
					ordererProcesses[i].Signal(syscall.SIGTERM)
					Eventually(ordererProcesses[i].Wait(), network.EventuallyTimeout).Should(Receive())

					By(fmt.Sprintf("Launching %s", orderer.Name))
					runner := network.OrdererRunner(orderer)
					ordererRunners[i] = runner
					proc := ifrit.Invoke(runner)
					ordererProcesses[i] = proc
					Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
				}
			}

			By("Restarting all orderers")
			restart()

			By("Waiting for followers to see the leader")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			By("Transacting on testchannel1")
			invokeQuery(network, peer, orderer, channel, 90)
			invokeQuery(network, peer, orderer, channel, 80)
			invokeQuery(network, peer, orderer, channel, 70)
			invokeQuery(network, peer, orderer, channel, 60)

			By("Planting last config block in the orderer's file system")
			configBlock := nwo.GetConfigBlock(network, peer, orderer, "systemchannel")
			err = ioutil.WriteFile(filepath.Join(testDir, "systemchannel_block.pb"), protoutil.MarshalOrPanic(configBlock), 0644)
			Expect(err).NotTo(HaveOccurred())

			By("Launching the added orderer")
			runner := network.OrdererRunner(orderer5)
			proc := ifrit.Invoke(runner)
			ordererProcesses = append(ordererProcesses, proc)
			Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())

			By("Waiting for the added orderer to see the leader")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			time.Sleep(time.Second * 10)

			By("Transact again")
			invokeQuery(network, peer, orderer, channel, 50)

			By("Ensuring added node participates in consensus")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Deciding on seq 7"))

			By("Ensure all nodes are in sync")
			assertBlockReception(map[string]int{channel: 7}, network.Orderers, peer, network)

			By("Killing the added node")
			proc.Signal(syscall.SIGTERM)
			Eventually(proc.Wait(), network.EventuallyTimeout).Should(Receive())

			By("Removing the added node from the channels")
			for _, channel := range []string{"systemchannel", "testchannel1"} {
				nwo.UpdateSmartBFTMetadata(network, peer, orderer, channel, func(md *smartbft.ConfigMetadata) {
					md.Consenters = md.Consenters[:4]
				})
			}

			assertBlockReception(map[string]int{
				"systemchannel": 3,
				"testchannel1":  8,
			}, network.Orderers[:4], peer, network)

			By("Restarting all orderers")
			restart()

			By("Launching the added orderer again")
			runner = network.OrdererRunner(orderer5)
			proc = ifrit.Invoke(runner)
			ordererProcesses[4] = proc
			Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())

			By("Ensuring the leader talks to existing followers")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			By("Transact again")
			invokeQuery(network, peer, orderer, channel, 40)

			By("Ensuring the existing nodes got the block")
			assertBlockReception(map[string]int{
				"systemchannel": 3,
				"testchannel1":  9,
			}, network.Orderers[:4], peer, network)

			By("Ensuring the removed node didn't get the blocks")
			assertBlockReception(map[string]int{
				"systemchannel": 2,
				"testchannel1":  7,
			}, []*nwo.Orderer{orderer5}, peer, network)

			By("Waiting for the removed node to start a view change")
			Eventually(runner.Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Heartbeat timeout expired, complaining about leader"))

			By("Ensuring the other nodes do not speak with the removed node")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("certificate extracted from TLS connection isn't authorized"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("certificate extracted from TLS connection isn't authorized"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("certificate extracted from TLS connection isn't authorized"))
		})

		It("smartbft multiple nodes view change", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			var ordererRunners []*ginkgomon.Runner
			for _, orderer := range network.Orderers {
				runner := network.OrdererRunner(orderer)
				ordererRunners = append(ordererRunners, runner)
				proc := ifrit.Invoke(runner)
				ordererProcesses = append(ordererProcesses, proc)
				Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
			}

			peerRunner := network.PeerGroupRunner()
			peerProcesses = ifrit.Invoke(peerRunner)
			Eventually(peerProcesses.Ready(), network.EventuallyTimeout).Should(BeClosed())

			By("Waiting for followers to see the leader")
			Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))
			Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 0"))

			peer := network.Peer("Org1", "peer0")

			channel := "testchannel1"

			orderer := network.Orderers[0]
			network.CreateAndJoinChannel(orderer, channel)

			assertBlockReception(map[string]int{"systemchannel": 1}, network.Orderers, peer, network)

			nwo.DeployChaincode(network, channel, orderer, nwo.Chaincode{
				Name:    "mycc",
				Version: "0.0",
				Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
				Ctor:    `{"Args":["init","a","100","b","200"]}`,
				Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
			})

			assertBlockReception(map[string]int{"testchannel1": 1}, network.Orderers, peer, network)

			By("Taking down the leader node")
			ordererProcesses[0].Signal(syscall.SIGTERM)
			Eventually(ordererProcesses[0].Wait(), network.EventuallyTimeout).Should(Receive())

			By("Submitting a request all followers to force a view change")
			for _, orderer := range []*nwo.Orderer{network.Orderers[1], network.Orderers[2], network.Orderers[3]} {
				sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
					ChannelID: channel,
					Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
					Name:      "mycc",
					Ctor:      `{"Args":["invoke","a","b","10"]}`,
					PeerAddresses: []string{
						network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
						network.PeerAddress(network.Peer("Org2", "peer1"), nwo.ListenPort),
					},
					WaitForEvent: false,
				})
				Expect(err).NotTo(HaveOccurred())
				Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
			}

			By("Waiting for circulating transaction to be re-proposed")
			assertBlockReception(map[string]int{"testchannel1": 2}, network.Orderers[1:], peer, network)

			By("Submitting transaction to the new leader")
			invokeQuery(network, peer, network.Orderers[1], channel, 80)
		})
	})
})

func invokeQuery(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, channel string, expectedBalance int) {
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: channel,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      "mycc",
		Ctor:      `{"Args":["invoke","a","b","10"]}`,
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer1"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	sess, err = network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: channel,
		Name:      "mycc",
		Ctor:      `{"Args":["query","a"]}`,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess).To(gbytes.Say(fmt.Sprintf("%d", expectedBalance)))
}

// assertBlockReception asserts that the given orderers have expected heights for the given channel--> height mapping
func assertBlockReception(expectedHeightsPerChannel map[string]int, orderers []*nwo.Orderer, p *nwo.Peer, n *nwo.Network) {
	assertReception := func(channelName string, blockSeq int) {
		var wg sync.WaitGroup
		wg.Add(len(orderers))
		for _, orderer := range orderers {
			go func(orderer *nwo.Orderer) {
				defer GinkgoRecover()
				defer wg.Done()
				waitForBlockReception(orderer, p, n, channelName, blockSeq)
			}(orderer)
		}
		wg.Wait()
	}

	var wg sync.WaitGroup
	wg.Add(len(expectedHeightsPerChannel))

	for channelName, blockSeq := range expectedHeightsPerChannel {
		go func(channelName string, blockSeq int) {
			defer GinkgoRecover()
			defer wg.Done()
			assertReception(channelName, blockSeq)
		}(channelName, blockSeq)
	}
	wg.Wait()
}

func waitForBlockReception(o *nwo.Orderer, submitter *nwo.Peer, network *nwo.Network, channelName string, blockSeq int) {
	c := commands.ChannelFetch{
		ChannelID:  channelName,
		Block:      "newest",
		OutputFile: "/dev/null",
		Orderer:    network.OrdererAddress(o, nwo.ListenPort),
	}
	Eventually(func() string {
		sess, err := network.OrdererAdminSession(o, submitter, c)
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s", sess.ExitCode(), string(sess.Err.Contents()))
		}
		sessErr := string(sess.Err.Contents())
		expected := fmt.Sprintf("Received block: %d", blockSeq)
		if strings.Contains(sessErr, expected) {
			return ""
		}
		return sessErr
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}
