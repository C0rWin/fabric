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
	"io/ioutil"
	"os"
	"syscall"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
)

var _ = Describe("EndToEnd Smart BFT configuration test", func() {
	var (
		testDir string
		client  *docker.Client
		network *nwo.Network

		networkProcess   ifrit.Process
		ordererProcesses []ifrit.Process
	)

	BeforeEach(func() {
		ordererProcesses = nil

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
		if network != nil {
			network.Cleanup()
		}
		for _, ordererInstance := range ordererProcesses {
			ordererInstance.Signal(syscall.SIGTERM)
			Eventually(ordererInstance.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		os.RemoveAll(testDir)
	})

	Describe("single node smartbft network with 1 org", func() {
		It("smartbft basic network", func() {
			network = nwo.New(nwo.BasicSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			ordererRunner := network.NetworkGroupRunner()
			networkProcess = ifrit.Invoke(ordererRunner)
			Eventually(networkProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

			orderer := network.Orderer("orderer")
			peer := network.Peer("Org1", "peer0")
			network.CreateChannel("testchannel", orderer, peer)
		})

		It("smartbft multiple nodes", func() {
			network = nwo.New(nwo.MultiNodeSmartBFT(), testDir, client, StartPort(), components)
			network.GenerateConfigTree()
			network.Bootstrap()

			ordererRunner := network.NetworkGroupRunner()
			networkProcess = ifrit.Invoke(ordererRunner)
			Eventually(networkProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

			orderer := network.Orderer("orderer1")
			network.CreateAndJoinChannel(orderer, "testchannel1")

			nwo.DeployChaincode(network, "testchannel", orderer, nwo.Chaincode{
				Name:              "mycc",
				Version:           "0.0",
				Path:              "github.com/hyperledger/fabric/integration/chaincode/keylevelep/cmd",
				Ctor:              `{"Args":["init"]}`,
				CollectionsConfig: "testdata/collection_config.json",
			})
		})
	})
})
