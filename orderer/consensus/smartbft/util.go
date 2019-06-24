/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/pem"

	"crypto/sha256"
	"encoding/hex"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

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
	endpoints, err := endpointConfigFromFromSupport(support)
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

	// TODO do we need this?
	//return &LedgerBlockPuller{
	//	Height:         support.Height,
	//	BlockRetriever: support,
	//	BlockPuller:    bp,
	//}, nil

	return bp, nil
}

// endpointConfigFromFromSupport extracts TLS CA certificates and endpoints from the ConsenterSupport
func endpointConfigFromFromSupport(support consensus.ConsenterSupport) ([]cluster.EndpointCriteria, error) {
	lastConfigBlock, err := lastConfigBlockFromSupport(support)
	if err != nil {
		return nil, err
	}
	endpointconf, err := cluster.EndpointconfigFromConfigBlock(lastConfigBlock)
	if err != nil {
		return nil, err
	}
	return endpointconf, nil
}

func lastConfigBlockFromSupport(support consensus.ConsenterSupport) (*common.Block, error) {
	lastBlockSeq := support.Height() - 1
	lastBlock := support.Block(lastBlockSeq)
	if lastBlock == nil {
		return nil, errors.Errorf("unable to retrieve block [%d]", lastBlockSeq)
	}
	lastConfigBlock, err := cluster.LastConfigBlock(lastBlock, support)
	if err != nil {
		return nil, err
	}
	return lastConfigBlock, nil
}

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

	txID := sha256.Sum256(append(sigHdr.Nonce, sigHdr.Creator...))
	return types.RequestInfo{
		ID:       hex.EncodeToString(txID[:]),
		ClientID: hex.EncodeToString(sha256.Sum256(sigHdr.Creator)[:]),
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
