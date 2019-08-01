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
	support     consensus.ConsenterSupport
	blockPuller BlockPuller
	clusterSize uint64
	logger      *flogging.FabricLogger
}

func NewSynchronizer(
	support consensus.ConsenterSupport,
	blockPuller BlockPuller,
	clusterSize uint64,
	logger *flogging.FabricLogger,
) (*Synchronizer, error) {
	s := &Synchronizer{
		support:     support,
		blockPuller: blockPuller,
		clusterSize: clusterSize,
		logger:      logger,
	}

	if logger == nil {
		s.logger = flogging.MustGetLogger("orderer.consensus.smartbft.sync").With("channel", support.ChainID())
	}

	return s, nil
}

func (s *Synchronizer) Close() {
	s.blockPuller.Close()
}

func (s *Synchronizer) Sync() (smartbftprotos.ViewMetadata, uint64) {
	metadata, sqn, err := s.synchronize()
	if err != nil {
		s.logger.Warnf("Could not synchronize with remote peers, returning state from local ledger; error: %s", err)
		block := s.support.Block(s.support.Height() - 1)
		return s.getViewMetadataLastConfigSqnFromBlock(block)
	}

	return metadata, sqn
}

func (s *Synchronizer) getViewMetadataLastConfigSqnFromBlock(block *common.Block) (smartbftprotos.ViewMetadata, uint64) {
	viewMetadata, err := getViewMetadataFromBlock(block)
	if err != nil {
		return smartbftprotos.ViewMetadata{}, 0
	}

	lastConfigSqn := s.support.Sequence()

	return viewMetadata, lastConfigSqn
}

func (s *Synchronizer) synchronize() (smartbftprotos.ViewMetadata, uint64, error) {

	heightByEndpoint, err := s.blockPuller.HeightsByEndpoints()
	if err != nil {
		return smartbftprotos.ViewMetadata{}, 0, errors.Wrap(err, "Cannot get HeightsByEndpoints")
	}

	heights := []uint64{}
	for _, value := range heightByEndpoint {
		heights = append(heights, value)
	}
	if len(heights) == 0 {
		return smartbftprotos.ViewMetadata{}, 0, errors.New("No cluster members to synchronize with")
	}

	targetHeight := s.computeTargetHeight(heights, s.clusterSize)
	startHeight := s.support.Height()
	currentHeight := startHeight
	s.logger.Debugf("Current height [%d], target height [%d]", currentHeight, targetHeight)

	for currentHeight < targetHeight {
		block := s.blockPuller.PullBlock(currentHeight)
		if block == nil {
			s.logger.Debugf("Failed to fetch block [%d] from cluster", currentHeight)
			break
		}

		if protoutil.IsConfigBlock(block) {
			s.support.WriteConfigBlock(block, nil)
		} else {
			s.support.WriteBlock(block, nil)
		}
		s.logger.Debugf("Fetched and committed block [%d] from cluster", currentHeight)
		currentHeight++
	}

	s.logger.Infof("Finished synchronizing with cluster, fetched %d blocks, starting from block [%d], up until and including block [%d]",
		currentHeight-startHeight, startHeight-1, currentHeight-1)
	lastBlock := s.support.Block(currentHeight - 1)
	if lastBlock == nil {
		return smartbftprotos.ViewMetadata{}, 0, errors.Errorf("Could not retrieve block [%d] from local ledger", currentHeight-1)
	}
	viewMetadata, lastConfigSqn := s.getViewMetadataLastConfigSqnFromBlock(lastBlock)
	s.logger.Debugf("Last block ViewMetadata=%s, lastConfigSqn=%d", viewMetadata, lastConfigSqn)

	return viewMetadata, lastConfigSqn, nil
}

// computeTargetHeight compute the target height to synchronize to.
//
// heights: a slice containing the heights of accessible peers, length must be >0.
// clusterSize: the cluster size, must be >0.
func (s *Synchronizer) computeTargetHeight(heights []uint64, clusterSize uint64) uint64 {
	sort.Slice(heights, func(i, j int) bool { return heights[i] > heights[j] }) // Descending
	bftF := (clusterSize - 1) / 3                                               // The number of tolerated byzantine faults
	lenH := len(heights)

	if uint64(lenH) < bftF+1 {
		return heights[lenH-1]
	}
	return heights[bftF]
}
