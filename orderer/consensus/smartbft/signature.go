/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/asn1"

	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
)

type Signature struct {
	LastConfigSeq     int64
	ConsenterMetadata []byte
	SignatureHeader   *common.SignatureHeader
	BlockHeader       *common.BlockHeader
}

func Unmarshal(bytes []byte) Signature {
	var sig Signature
	asn1.Unmarshal(bytes, &sig)
}

func (sig Signature) Marshal() []byte {
	bytes, err := asn1.Marshal(sig)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (sig Signature) AsBytes(signer identity.Signer) []byte {
	blockSignature := &common.MetadataSignature{
		SignatureHeader: protoutil.MarshalOrPanic(sig.SignatureHeader),
	}

	blockSignatureValue := protoutil.MarshalOrPanic(&common.OrdererBlockMetadata{
		LastConfig:        &common.LastConfig{Index: uint64(sig.LastConfigSeq)},
		ConsenterMetadata: sig.ConsenterMetadata,
	})

	msg2Sign := util.ConcatenateBytes(blockSignatureValue, blockSignature.SignatureHeader, protoutil.BlockHeaderBytes(sig.BlockHeader))
	return msg2Sign
}
