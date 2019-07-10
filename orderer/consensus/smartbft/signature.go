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
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

type Signature struct {
	ConsenterMetadata    []byte
	SignatureHeader      *common.SignatureHeader
	BlockHeader          *common.BlockHeader
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
	sigHdr := protoutil.MarshalOrPanic(sig.SignatureHeader)
	msg2Sign := util.ConcatenateBytes(sig.OrdererBlockMetadata, sigHdr, protoutil.BlockHeaderBytes(sig.BlockHeader))
	return msg2Sign
}

func proposalToBlock(proposal types.Proposal) (*common.Block, error) {
	block := &common.Block{}
	if err := proto.Unmarshal(proposal.Header, block.Header); err != nil {
		return nil, errors.Wrap(err, "bad header")
	}

	tuple := ByteBufferTuple{}
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
