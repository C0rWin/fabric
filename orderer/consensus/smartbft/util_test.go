/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"io/ioutil"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/mocks/common/multichannel"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewBlockPuller(t *testing.T) {
	ca, err := tlsgen.NewCA()
	assert.NoError(t, err)

	blockBytes, err := ioutil.ReadFile("testdata/mychannel.block")
	assert.NoError(t, err)

	goodConfigBlock := &common.Block{}
	assert.NoError(t, proto.Unmarshal(blockBytes, goodConfigBlock))

	lastBlock := &common.Block{
		Metadata: &common.BlockMetadata{
			Metadata: [][]byte{{}, utils.MarshalOrPanic(&common.Metadata{
				Value: utils.MarshalOrPanic(&common.LastConfig{Index: 42}),
			})},
		},
	}

	cs := &multichannel.ConsenterSupport{
		HeightVal: 100,
		BlockByIndex: map[uint64]*common.Block{
			42: goodConfigBlock,
			99: lastBlock,
		},
	}

	dialer := &cluster.PredicateDialer{
		ClientConfig: comm.ClientConfig{
			SecOpts: &comm.SecureOptions{
				Certificate: ca.CertBytes(),
			},
		},
	}

	blockPuller, err := newBlockPuller(cs, dialer,
		localconfig.Cluster{
			ReplicationMaxRetries: 2,
		})
	assert.NoError(t, err)
	assert.NotNil(t, blockPuller)
	blockPuller.Close()
}
