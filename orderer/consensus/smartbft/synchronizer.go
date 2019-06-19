/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/consensus"
)

type Synchronizer struct {
	support       consensus.ConsenterSupport
	baseDialer    *cluster.PredicateDialer
	clusterConfig localconfig.Cluster
	blockPuller   BlockPuller
}

func NewSynchronizer(
	support consensus.ConsenterSupport,
	baseDialer *cluster.PredicateDialer,
	clusterConfig localconfig.Cluster) (*Synchronizer, error) {

	puller, err := newBlockPuller(support, baseDialer, clusterConfig)
	if err != nil {
		return nil, err
	}

	s := &Synchronizer{
		support:       support,
		baseDialer:    baseDialer,
		clusterConfig: clusterConfig,
		blockPuller:   puller,
	}
	//TODO
	return s, nil
}

func (s *Synchronizer) Close() {
	//TODO
}

func (s *Synchronizer) Sync() (smartbftprotos.ViewMetadata, uint64) {
	//TODO
	return smartbftprotos.ViewMetadata{}, 0
}
