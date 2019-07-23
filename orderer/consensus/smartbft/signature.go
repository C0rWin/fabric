/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/asn1"

	"github.com/SmartBFT-Go/consensus/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/pkg/errors"
)

type Signature struct {
	ConsenterMetadata    []byte
	SignatureHeader      []byte
	BlockHeader          []byte
	OrdererBlockMetadata []byte
}

func (sig *Signature) Unmarshal(bytes []byte) *Signature {
	asn1.Unmarshal(bytes, sig)
	return sig
}

func (sig *Signature) Marshal() []byte {
	bytes, err := asn1.Marshal(*sig)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (sig Signature) AsBytes(signer identity.Signer) []byte {
	msg2Sign := util.ConcatenateBytes(sig.OrdererBlockMetadata, sig.SignatureHeader, sig.BlockHeader)
	return msg2Sign
}

func ProposalToBlock(proposal types.Proposal) (*common.Block, error) {
	// initialize block with empty fields
	block := &common.Block{
		Header:   &common.BlockHeader{},
		Data:     &common.BlockData{},
		Metadata: &common.BlockMetadata{},
	}

	if len(proposal.Header) == 0 {
		return nil, errors.New("proposal header cannot be nil")
	}
	if err := proto.Unmarshal(proposal.Header, block.Header); err != nil {
		return nil, errors.Wrap(err, "bad header")
	}

	if len(proposal.Payload) == 0 {
		return nil, errors.New("proposal payload cannot be nil")
	}

	tuple := &ByteBufferTuple{}
	if err := tuple.FromBytes(proposal.Payload); err != nil {
		return nil, errors.Wrap(err, "bad payload and metadata tuple")
	}

	if err := proto.Unmarshal(tuple.A, block.Data); err != nil {
		return nil, errors.Wrap(err, "bad payload")
	}

	if err := proto.Unmarshal(tuple.B, block.Metadata); err != nil {
		return nil, errors.Wrap(err, "bad metadata")
	}
	return block, nil
}
