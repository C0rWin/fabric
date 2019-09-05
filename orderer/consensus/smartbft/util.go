/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	utils2 "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// newBlockPuller creates a new block puller
func newBlockPuller(
	support consensus.ConsenterSupport,
	baseDialer *cluster.PredicateDialer,
	clusterConfig localconfig.Cluster) (BlockPuller, error) {

	verifyBlockSequence := func(blocks []*common.Block, _ string) error {
		return cluster.VerifyBlocks(blocks, support)
	}

	stdDialer := &cluster.StandardDialer{
		ClientConfig: baseDialer.ClientConfig.Clone(),
	}
	stdDialer.ClientConfig.AsyncConnect = false
	stdDialer.ClientConfig.SecOpts.VerifyCertificate = nil

	// Extract the TLS CA certs and endpoints from the configuration,
	endpoints, err := etcdraft.EndpointconfigFromFromSupport(support)
	if err != nil {
		return nil, err
	}

	der, _ := pem.Decode(stdDialer.ClientConfig.SecOpts.Certificate)
	if der == nil {
		return nil, errors.Errorf("client certificate isn't in PEM format: %v",
			string(stdDialer.ClientConfig.SecOpts.Certificate))
	}

	bp := &cluster.BlockPuller{
		VerifyBlockSequence: verifyBlockSequence,
		Logger:              flogging.MustGetLogger("orderer.common.cluster.puller"),
		RetryTimeout:        clusterConfig.ReplicationRetryTimeout,
		MaxTotalBufferBytes: clusterConfig.ReplicationBufferSize,
		FetchTimeout:        clusterConfig.ReplicationPullTimeout,
		Endpoints:           endpoints,
		Signer:              support,
		TLSCert:             der.Bytes,
		Channel:             support.ChainID(),
		Dialer:              stdDialer,
	}

	return bp, nil
}

func getViewMetadataFromBlock(block *common.Block) (smartbftprotos.ViewMetadata, error) {
	if block.Header.Number == 0 {
		// Genesis block has no prior metadata so we just return an un-initialized metadata
		return smartbftprotos.ViewMetadata{}, nil
	}

	signatureMetadata := utils2.GetMetadataFromBlockOrPanic(block, common.BlockMetadataIndex_SIGNATURES)
	ordererMD := &common.OrdererBlockMetadata{}
	if err := proto.Unmarshal(signatureMetadata.Value, ordererMD); err != nil {
		return smartbftprotos.ViewMetadata{}, errors.Wrap(err, "failed unmarshaling OrdererBlockMetadata")
	}

	var viewMetadata smartbftprotos.ViewMetadata
	if err := proto.Unmarshal(ordererMD.ConsenterMetadata, &viewMetadata); err != nil {
		return smartbftprotos.ViewMetadata{}, err
	}

	return viewMetadata, nil
}

// RequestInspector inspects incomming requests and validates serialized identity
type RequestInspector struct {
	ValidateIdentityStructure func(identity *msp.SerializedIdentity) error
}

func (ri *RequestInspector) RequestID(rawReq []byte) types.RequestInfo {
	req, err := ri.unwrapReq(rawReq)
	if err != nil {
		return types.RequestInfo{}
	}
	reqInfo, err := ri.requestIDFromSigHeader(req.sigHdr)
	if err != nil {
		return types.RequestInfo{}
	}
	return reqInfo
}

type request struct {
	sigHdr   *common.SignatureHeader
	envelope *common.Envelope
}

func (ri *RequestInspector) requestIDFromSigHeader(sigHdr *common.SignatureHeader) (types.RequestInfo, error) {
	sID := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(sigHdr.Creator, sID); err != nil {
		return types.RequestInfo{}, errors.Wrap(err, "identity isn't an MSP Identity")
	}

	if err := ri.ValidateIdentityStructure(sID); err != nil {
		return types.RequestInfo{}, err
	}

	var preimage []byte
	preimage = append(preimage, sigHdr.Nonce...)
	preimage = append(preimage, sigHdr.Creator...)
	txID := sha256.Sum256(preimage)
	clientID := sha256.Sum256(sigHdr.Creator)
	return types.RequestInfo{
		ID:       hex.EncodeToString(txID[:]),
		ClientID: hex.EncodeToString(clientID[:]),
	}, nil
}

func (ri *RequestInspector) unwrapReq(req []byte) (*request, error) {
	envelope, err := utils2.UnmarshalEnvelope(req)
	if err != nil {
		return nil, err
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling payload")
	}

	if payload.Header == nil {
		return nil, errors.Errorf("no header in payload")
	}

	sigHdr := &common.SignatureHeader{}
	if err := proto.Unmarshal(payload.Header.SignatureHeader, sigHdr); err != nil {
		return nil, err
	}

	return &request{
		sigHdr:   sigHdr,
		envelope: envelope,
	}, nil
}

// ConfigurationEnvelop extract configuration envelop
func ConfigurationEnvelop(configBlock *common.Block) (*common.ConfigEnvelope, error) {
	envelopeConfig, err := utils2.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract envelop from block")
	}

	payload, err := utils2.UnmarshalPayload(envelopeConfig.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal envelop payload")
	}

	configEnvelope, err := configtx.UnmarshalConfigEnvelope(payload.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal configuration payload")
	}
	return configEnvelope, nil
}

// ConsenterCertificate denotes a TLS certificate of a consenter
type ConsenterCertificate []byte

// IsConsenterOfChannel returns whether the caller is a consenter of a channel
// by inspecting the given configuration block.
// It returns nil if true, else returns an error.
func (conCert ConsenterCertificate) IsConsenterOfChannel(configBlock *common.Block) error {
	if configBlock == nil {
		return errors.New("nil block")
	}
	envelopeConfig, err := utils2.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return err
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelopeConfig)
	if err != nil {
		return err
	}
	oc, exists := bundle.OrdererConfig()
	if !exists {
		return errors.New("no orderer config in bundle")
	}
	if oc.ConsensusType() != "smartbft" {
		return errors.New("not an etcdraft config block")
	}
	m := &smartbft.ConfigMetadata{}
	if err := proto.Unmarshal(oc.ConsensusMetadata(), m); err != nil {
		return err
	}

	for _, consenter := range m.Consenters {
		if bytes.Equal(conCert, consenter.ServerTlsCert) || bytes.Equal(conCert, consenter.ClientTlsCert) {
			return nil
		}
	}
	return cluster.ErrNotInChannel
}

func sanitizeIdentity(identity []byte, logger *flogging.FabricLogger) []byte {
	sID := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(identity, sID); err != nil {
		logger.Panicf("Failed unmarshaling identity %s", string(identity))
	}

	der, _ := pem.Decode(sID.IdBytes)
	cert, err := x509.ParseCertificate(der.Bytes)
	if err != nil {
		logger.Panicf("Failed parsing certificate %s: %v", string(sID.IdBytes), err)
	}

	r, s, err := utils.UnmarshalECDSASignature(cert.Signature)
	if err != nil {
		logger.Panicf("Failed unmarshaling ECDSA signature on identity: %s", string(sID.IdBytes))
	}

	// TODO: Make this robust... search the signature algorithm
	// and match it to the curve.
	curveOrderUsedByCryptoGen := elliptic.P256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrderUsedByCryptoGen, 1)
	// Low S, nothing to do here!
	if s.Cmp(halfOrder) != 1 {
		return identity
	}
	// Else it's high-S, so shift it below half the order.
	s.Sub(curveOrderUsedByCryptoGen, s)

	var newCert certificate
	_, err = asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		logger.Panicf("Failed unmarshaling certificate: %v", err)
	}

	newSig, _ := utils.MarshalECDSASignature(r, s)
	newCert.SignatureValue = asn1.BitString{Bytes: newSig, BitLength: len(newSig) * 8}

	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)

	sID.IdBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newRaw})
	return utils2.MarshalOrPanic(sID)
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
