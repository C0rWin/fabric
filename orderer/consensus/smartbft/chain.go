/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import "github.com/hyperledger/fabric/protos/common"

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// BlockPuller is used to pull blocks from other OSN
type BlockPuller interface {
	PullBlock(seq uint64) *common.Block
	HeightsByEndpoints() (map[string]uint64, error)
	Close()
}
