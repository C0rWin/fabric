/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"sort"

	"github.com/SmartBFT-Go/consensus/smartbftprotos"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

type Synchronizer struct {
	UpdateLastHash func(block *common.Block)
	Support        consensus.ConsenterSupport
	BlockPuller    BlockPuller
	ClusterSize    uint64
	Logger         *flogging.FabricLogger
}

func (s *Synchronizer) Close() {
	s.BlockPuller.Close()
}

func (s *Synchronizer) Sync() (smartbftprotos.ViewMetadata, uint64) {
	metadata, sqn, err := s.synchronize()
	if err != nil {
		s.Logger.Warnf("Could not synchronize with remote peers due to %s, returning state from local ledger", err)
		block := s.Support.Block(s.Support.Height() - 1)
		return s.getViewMetadataLastConfigSqnFromBlock(block)
	}

	return metadata, sqn
}

func (s *Synchronizer) getViewMetadataLastConfigSqnFromBlock(block *common.Block) (smartbftprotos.ViewMetadata, uint64) {
	viewMetadata, err := getViewMetadataFromBlock(block)
	if err != nil {
		return smartbftprotos.ViewMetadata{}, 0
	}

	lastConfigSqn := s.Support.Sequence()

	return viewMetadata, lastConfigSqn
}

func (s *Synchronizer) synchronize() (smartbftprotos.ViewMetadata, uint64, error) {
	defer s.BlockPuller.Close()
	heightByEndpoint, err := s.BlockPuller.HeightsByEndpoints()
	if err != nil {
		return smartbftprotos.ViewMetadata{}, 0, errors.Wrap(err, "cannot get HeightsByEndpoints")
	}

	s.Logger.Infof("HeightsByEndpoints: %v", heightByEndpoint)

	if len(heightByEndpoint) == 0 {
		return smartbftprotos.ViewMetadata{}, 0, errors.New("no cluster members to synchronize with")
	}

	var heights []uint64
	for _, value := range heightByEndpoint {
		heights = append(heights, value)
	}

	targetHeight := s.computeTargetHeight(heights)
	startHeight := s.Support.Height()
	if startHeight >= targetHeight {
		return smartbftprotos.ViewMetadata{}, 0, errors.Errorf("already at height of %d", targetHeight)
	}

	targetSeq := targetHeight - 1
	seq := startHeight

	s.Logger.Debugf("Will fetch sequences [%d-%d]", seq, targetSeq)

	var lastPulledBlock *common.Block
	for seq <= targetSeq {
		block := s.BlockPuller.PullBlock(seq)
		if block == nil {
			s.Logger.Debugf("Failed to fetch block [%d] from cluster", seq)
			break
		}
		if protoutil.IsConfigBlock(block) {
			s.Support.WriteConfigBlock(block, nil)
		} else {
			s.Support.WriteBlock(block, nil)
		}
		s.Logger.Debugf("Fetched and committed block [%d] from cluster", seq)
		lastPulledBlock = block
		seq++
	}

	if lastPulledBlock == nil {
		return smartbftprotos.ViewMetadata{}, 0, errors.Errorf("failed pulling block %d", seq)
	}

	s.UpdateLastHash(lastPulledBlock)

	startSeq := startHeight
	s.Logger.Infof("Finished synchronizing with cluster, fetched %d blocks, starting from block [%d], up until and including block [%d]",
		seq-startSeq+1, startSeq, lastPulledBlock.Header.Number)

	viewMetadata, lastConfigSqn := s.getViewMetadataLastConfigSqnFromBlock(lastPulledBlock)

	s.Logger.Infof("Returning view metadata of %v, lastConfigSeq %d", viewMetadata, lastConfigSqn)
	return viewMetadata, lastConfigSqn, nil
}

// computeTargetHeight compute the target height to synchronize to.
//
// heights: a slice containing the heights of accessible peers, length must be >0.
// clusterSize: the cluster size, must be >0.
func (s *Synchronizer) computeTargetHeight(heights []uint64) uint64 {
	sort.Slice(heights, func(i, j int) bool { return heights[i] > heights[j] }) // Descending
	f := uint64(s.ClusterSize-1) / 3                                            // The number of tolerated byzantine faults
	lenH := uint64(len(heights))

	s.Logger.Debugf("Heights: %v", heights)

	if lenH < f+1 {
		s.Logger.Debugf("Returning %d", heights[0])
		return heights[int(lenH)-1]
	}
	s.Logger.Debugf("Returning %d", heights[f])
	return heights[f]
}
