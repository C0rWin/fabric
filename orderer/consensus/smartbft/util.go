/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protoutil"
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
		Config: baseDialer.Config.Clone(),
	}
	stdDialer.Config.AsyncConnect = false
	stdDialer.Config.SecOpts.VerifyCertificate = nil

	// Extract the TLS CA certs and endpoints from the configuration,
	endpoints, err := etcdraft.EndpointconfigFromFromSupport(support)
	if err != nil {
		return nil, err
	}

	der, _ := pem.Decode(stdDialer.Config.SecOpts.Certificate)
	if der == nil {
		return nil, errors.Errorf("client certificate isn't in PEM format: %v",
			string(stdDialer.Config.SecOpts.Certificate))
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

	ordererMetadata := protoutil.GetMetadataFromBlockOrPanic(block, common.BlockMetadataIndex_ORDERER)

	var viewMetadata smartbftprotos.ViewMetadata
	if err := proto.Unmarshal(ordererMetadata.Value, &viewMetadata); err != nil {
		return smartbftprotos.ViewMetadata{}, err
	}

	return viewMetadata, nil
}

func getViewMetadataLastConfigSqnFromBlock(block *common.Block) (smartbftprotos.ViewMetadata, uint64) {
	viewMetadata, err := getViewMetadataFromBlock(block)
	if err != nil {
		return smartbftprotos.ViewMetadata{}, 0
	}

	sqn := protoutil.GetLastConfigIndexFromBlockOrPanic(block)

	return viewMetadata, sqn
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
	if err := proto.Unmarshal(sigHdr.Creator, sigHdr); err != nil {
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
	envelope, err := protoutil.UnmarshalEnvelope(req)
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
	envelopeConfig, err := protoutil.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract envelop from block")
	}

	payload, err := protoutil.UnmarshalPayload(envelopeConfig.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal envelop payload")
	}

	configEnvelope, err := configtx.UnmarshalConfigEnvelope(payload.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal configuration payload")
	}
	return configEnvelope, nil
}
