package bft

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/internal/pkg/identity"
)

//go:generate counterfeiter -o fake/signer.go --fake-name Signer . signer
type signer interface {
	identity.SignerSerializer
}

//go:generate counterfeiter -o fake/ab_deliver_client.go --fake-name DeliverClient . abDeliverClient
type abDeliverClient interface {
	orderer.AtomicBroadcast_DeliverClient
}

func TestBFTBlocksprovider(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BFT Blocksprovider Suite")
}
