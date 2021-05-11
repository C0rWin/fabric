/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"encoding/asn1"
	"encoding/base64"
	"math"
	"runtime/debug"
	"sync"
	"time"

	cs "github.com/SmartBFT-Go/randomcommittees"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/types"
	. "github.com/hyperledger/fabric/orderer/consensus/smartbft/types"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer/smartbft"
	"github.com/pkg/errors"
)

type CommitteeTracker struct {
	committeeDisabled bool
	ledger            Ledger
	logger            *flogging.FabricLogger
	cr                *CommitteeRetriever
}

func committeeHasPublicKeysDefined(nodes committee.Nodes) bool {
	for _, n := range nodes {
		if len(n.PubKey) == 0 {
			return false
		}
	}
	return true
}

func (ct *CommitteeTracker) CurrentCommittee() committee.Nodes {
	if ct.cr == nil {
		ct.cr = &CommitteeRetriever{
			committeeDisabled:     ct.committeeDisabled,
			NewCommitteeSelection: cs.NewCommitteeSelection,
			Ledger:                ct.ledger,
			Logger:                ct.logger,
		}
	}

	committee, err := ct.cr.CurrentCommittee()
	if err != nil {
		ct.logger.Panicf("Failed determining current committee: %v\n%s", err, debug.Stack())
	}

	return committee
}

//go:generate mockery -dir . -name CommitteeSelection -case underscore -output mocks

type CommitteeSelection interface {
	committee.Selection
}

// CommitteeRetriever retrieves the committee.
type CommitteeRetriever struct {
	lock            sync.RWMutex
	latestHeight    uint64
	latestCommittee committee.Nodes

	committeeDisabled     bool
	NewCommitteeSelection func(logger committee.Logger) committee.Selection
	Ledger                Ledger
	Logger                *flogging.FabricLogger
}

func (cr *CommitteeRetriever) CurrentState(forCommit bool) committee.State {
	emptyState, err := cs.StateFromBytes(nil)
	if err != nil {
		cr.Logger.Panicf("Failed initializing empty state: %v", err)
	}

	if cr.committeeDisabled {
		cr.Logger.Debugf("Committee selection is disabled, returning empty state")
		return emptyState
	}

	lastBlock := LastBlockFromLedgerOrPanic(cr.Ledger, cr.Logger)
	md, err := CommitteeMetadataFromBlock(lastBlock)
	if err != nil {
		cr.Logger.Panicf("Failed extracting committee metadata from block %d: %v", lastBlock.Header.Number, err)
	}

	if md == nil {
		cr.Logger.Debugf("Committee metadata of current block is nil, returning an empty state")
		return emptyState
	}

	if forCommit {
		if lastBlock.Header.Number == uint64(md.CommitteeShiftAt) {
			cr.Logger.Debugf("Last block was a committee change, returning an empty state")
			return emptyState
		}
		nonEmptyState, err := cs.StateFromBytes(md.State)
		if err != nil {
			cr.Logger.Panicf("Failed initializing state: %v", err)
		}
		cr.Logger.Debugf("Requested state for commit, returning a state of %d bytes", len(md.State))

		return nonEmptyState
	}

	var rawState []byte
	if len(md.State) > 0 {
		cr.Logger.Debugf("Current block (%d) contains %d bytes of state", lastBlock.Header.Number, len(md.State))
		rawState = md.State
	} else {
		cr.Logger.Debugf("Current block (%d) has no state and its final state index is %d and its last committee shift index is %d ,"+
			"retrieving the state from block %d", lastBlock.Header.Number, md.FinalStateIndex, md.CommitteeShiftAt, md.FinalStateIndex)
		block := cr.Ledger.Block(uint64(md.FinalStateIndex))

		md, err := CommitteeMetadataFromBlock(block)
		if err != nil {
			cr.Logger.Panicf("Failed extracting committee metadata from block %d: %v", block.Header.Number, err)
		}
		rawState = md.State
	}

	nonEmptyState, err := cs.StateFromBytes(rawState)
	if err != nil {
		cr.Logger.Panicf("Failed initializing state: %v", err)
	}

	return nonEmptyState
}

// CurrentCommittee returns the current nodes of the committee,
// and the latest state of the committee.
// In case the committee selection is disabled, it returns an empty slice.
func (cr *CommitteeRetriever) CurrentCommittee() (committee.Nodes, error) {
	cr.lock.RLock()
	height := cr.latestHeight
	cached := cr.latestCommittee
	cr.lock.RUnlock()

	if cr.Ledger.Height() == height {
		cr.Logger.Debugf("Returning cached result for height %d: %v", height, cached)
		return cached, nil
	}

	cr.lock.Lock()
	defer cr.lock.Unlock()

	// Backup ledger reference
	realLedger := cr.Ledger

	// Restore real ledger after we're done
	defer func() {
		cr.Ledger = realLedger
	}()

	height = realLedger.Height()

	cr.Ledger = &frozenLedger{
		height: height,
		Ledger: realLedger,
	}

	cached, err := cr.currentCommittee()
	if err != nil {
		return nil, err
	}

	cr.latestCommittee = cached
	cr.latestHeight = height

	cr.Logger.Debugf("Caching result for height %d: %v", height, cached)

	return cached, nil

}

type frozenLedger struct {
	height uint64
	Ledger
}

func (fl *frozenLedger) Height() uint64 {
	return fl.height
}

// CurrentCommittee returns the current nodes of the committee,
// and the latest state of the committee.
// In case the committee selection is disabled, it returns an empty slice.
func (cr *CommitteeRetriever) currentCommittee() (committee.Nodes, error) {
	lastBlock := LastBlockFromLedgerOrPanic(cr.Ledger, cr.Logger)
	lastConfigBlock := LastConfigBlockFromLedgerOrPanic(cr.Ledger, cr.Logger)
	cr.Logger.Debugf("Requesting committee for block %d where the latest config block is %d", lastBlock.Header.Number+1, lastConfigBlock.Header.Number)
	committeeMetadataOfLastBlock, err := CommitteeMetadataFromBlock(lastBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting committee metadata from latest block")
	}

	config, err := consensusMDFromBlock(lastConfigBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting consensus config from latest config block")
	}

	nodeConf, err := RemoteNodesFromConfigBlock(lastConfigBlock, 0, cr.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting node config from latest config block")
	}

	noCommitteeSelection, err := cr.disabled(config, nodeConf)
	if err != nil {
		return nil, err
	}

	if noCommitteeSelection {
		cr.Logger.Debugf("Committee selection is disabled, returning all nodes")
		return nodeConf.NodesNoPubKeys(cr.Logger), nil
	}

	if committeeMetadataOfLastBlock == nil {
		genesisCommittee, err := cr.genesisCommittee(int64(lastBlock.Header.Number))
		cr.Logger.Debugf("Committee metadata of last block (%d) not defined yet, this is either a new channel or an upgrade from "+
			"an older version, returning all candidate nodes, returning %v", lastBlock.Header.Number, genesisCommittee)
		return genesisCommittee, err
	}

	reconstructionSharesBlock := cr.Ledger.Block(uint64(committeeMetadataOfLastBlock.CommitteeShiftAt))

	committeeMD, err := CommitteeMetadataFromBlock(reconstructionSharesBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting committee metadata from latest reconstruction share block")
	}

	// It might be that we have some metadata but we're still in the first committee ever,
	// which includes all nodes.
	// We can identify that by looking at the CommitteeShiftAt which will be zero.
	if committeeMD == nil {
		genesisCommittee, err := cr.genesisCommittee(committeeMetadataOfLastBlock.GenesisConfigAt)
		cr.Logger.Debugf("This is the first committee, returning %v", genesisCommittee)
		return genesisCommittee, err
	}

	// Else, we have some committee metadata defined.
	// We need to figure what is the latest state that was used
	// to pick the committee.
	// This resides in the FinalStateIndex.
	// Afterwards we need to fetch the block where we have reconstruction shares.
	cr.Logger.Debugf("Will reconstruct the committee for block %d based on state from block %d and reconstruction shares "+
		"from block %d", lastBlock.Header.Number+1, committeeMD.FinalStateIndex, committeeMD.CommitteeShiftAt)

	signatureMetadata := &common.Metadata{}
	if err := proto.Unmarshal(reconstructionSharesBlock.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], signatureMetadata); err != nil {
		return nil, errors.Wrapf(err, "failed unmarshaling signatures from block %d", committeeMD.CommitteeShiftAt)
	}

	var reconShares []committee.ReconShare
	for _, sigMD := range signatureMetadata.Signatures {
		cf := &smartbft.CommitteeFeedback{}
		if err := proto.Unmarshal(sigMD.CommitteeAuxiliaryInput, cf); err != nil {
			return nil, errors.Wrap(err, "failed unmarshaling committee auxiliary input in signature")
		}

		for _, rawReconshare := range cf.Reconshares {
			reconShare := committee.ReconShare{}
			if _, err := asn1.Unmarshal(rawReconshare, &reconShare); err != nil {
				return nil, errors.Wrapf(err, "failed unmarshaling reconshare %s", base64.StdEncoding.EncodeToString(rawReconshare))
			}
			reconShares = append(reconShares, reconShare)
		}
	}

	cr.Logger.Debugf("Detected %d ReconShares in block %d", len(reconShares), reconstructionSharesBlock.Header.Number)

	consensusMD, err := consensusMDFromBlock(lastConfigBlock)
	if err != nil {
		return nil, err
	}

	var committeeConfig *smartbft.CommitteeConfig
	if consensusMD.Options != nil {
		committeeConfig = consensusMD.Options.CommitteeConfig
	}

	if committeeConfig == nil {
		committeeConfig = defaultCommitteeConfig
	}

	cfg := parseCommitteeConfig(nodeConf, committeeConfig, cr.Logger)

	committeeSelection := cr.NewCommitteeSelection(cr.Logger)
	cr.Logger.Infof("Determining committee for block %d with nodes %v", lastBlock.Header.Number+1, committeeMD.CommitteeAtShift.IDs())
	if err := committeeSelection.Initialize(math.MaxInt32, nil, committeeMD.CommitteeAtShift); err != nil {
		return nil, errors.Wrap(err, "failed initializing committee")
	}
	currentCommitteeState, err := cr.latestState(committeeMD.FinalStateIndex)
	if err != nil {
		return nil, errors.Wrapf(err, "failed fetching latest state from block %d", committeeMetadataOfLastBlock.CommitteeShiftAt)
	}

	// Load latest state by processing an empty input
	if _, _, err := committeeSelection.Process(currentCommitteeState, committee.Input{}); err != nil {
		return nil, errors.Wrap(err, "failed loading state")
	}

	feedback, _, err := committeeSelection.Process(currentCommitteeState, committee.Input{
		NextConfig:  cfg,
		ReconShares: cr.filterInvalidReconShares(committeeSelection, reconShares),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed deciding the next committee")
	}

	if len(feedback.NextCommittee) == 0 {
		return nil, errors.Errorf("next committee is an empty set")
	}

	id2pubKey := make(map[int32][]byte)

	for _, node := range cfg.Nodes {
		id2pubKey[node.ID] = node.PubKey
	}

	var nodes committee.Nodes
	for _, id := range feedback.NextCommittee {
		nodes = append(nodes, committee.Node{
			ID:     id,
			PubKey: id2pubKey[id],
		})
	}

	cr.Logger.Debugf("Returning committee for block %d: %v", lastBlock.Header.Number+1, nodes.IDs())
	return nodes, nil

}

func (cr *CommitteeRetriever) filterInvalidReconShares(cs committee.Selection, reconShares []committee.ReconShare) []committee.ReconShare {
	var res []committee.ReconShare

	for _, rcs := range reconShares {
		cr.Logger.Debugf("Verifying ReconShare from %d about %d", rcs.From, rcs.About)
		if err := cs.VerifyReconShare(rcs); err != nil {
			cr.Logger.Warnf("Reconstruction share of %d about %d is invalid: %v", rcs.From, rcs.About, err)
			continue
		}
		res = append(res, rcs)
	}

	cr.Logger.Debugf("Returning %d ReconShares", len(res))

	return res
}

func (cr *CommitteeRetriever) genesisCommittee(lastBlockIndex int64) (committee.Nodes, error) {
	cr.Logger.Infof("Retrieving committee of genesis config at block %d", lastBlockIndex)
	block := cr.Ledger.Block(uint64(lastBlockIndex))
	if block == nil {
		cr.Logger.Panicf("Failed retrieving last block")
	}
	lastConfigBlock, err := cluster.LastConfigBlock(block, cr.Ledger)
	if err != nil {
		return nil, err
	}
	nodeConf, err := RemoteNodesFromConfigBlock(lastConfigBlock, 0, cr.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting node config from latest config block")
	}
	return nodeConf.Nodes(cr.Logger), nil
}

func (cr *CommitteeRetriever) latestState(finalStateIndex int64) (committee.State, error) {
	lastStateBlock := cr.Ledger.Block(uint64(finalStateIndex))

	committeeMD, err := CommitteeMetadataFromBlock(lastStateBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed extracting committee metadata from latest state block")
	}

	var rawState []byte

	if committeeMD != nil {
		rawState = committeeMD.State
	}

	state, err := cs.StateFromBytes(rawState)
	if err != nil {
		cr.Logger.Warnf("Found invalid state: %s", base64.StdEncoding.EncodeToString(committeeMD.State))
		return nil, errors.Wrap(err, "failed initializing committee state")
	}
	return state, nil
}

func (cr *CommitteeRetriever) disabled(config *smartbft.ConfigMetadata, nodeConf *nodeConfig) (bool, error) {
	if cr.committeeDisabled {
		return true, nil
	}

	if config.Options.CommitteeConfig == nil {
		cr.Logger.Debugf("Committee selection is not set")
		return true, nil
	}

	if config.Options.CommitteeConfig.Disabled {
		cr.Logger.Debugf("Committee selection is disabled,")
		return true, nil
	}

	if len(nodeConf.id2SectionPK) < 4 {
		cr.Logger.Debugf("We only have %d selection public keys defined", len(nodeConf.id2SectionPK))
		return true, nil
	}

	return false, nil
}

func CommitteeMetadataForProposal(
	logger *flogging.FabricLogger,
	commitment, newState []byte,
	prevCommitteeMD *types.CommitteeMetadata,
	blockNum int64,
	expectedCommitters int,
	committeeMinimumLifespan uint32,
	currentCommittee committee.Nodes,
	id int32,
) *types.CommitteeMetadata {
	committeeMD := &types.CommitteeMetadata{}

	logger.Debugf("Computing metadata for block %d", blockNum)

	if !committeeHasPublicKeysDefined(currentCommittee) {
		logger.Debugf("Current committee lacks public keys, returning an empty CommitteeMetadata")
		return committeeMD
	}

	var prevStateSize int
	if prevCommitteeMD == nil {
		committeeMD.GenesisConfigAt = blockNum - 1
		logger.Debugf("This is the first committee metadata, setting genesis config to be %d", committeeMD.GenesisConfigAt)
	}

	committeeMD.CommitteeSize = int32(len(currentCommittee))

	if prevCommitteeMD != nil {
		prevStateSize = len(prevCommitteeMD.State)
		committeeMD.GenesisConfigAt = prevCommitteeMD.GenesisConfigAt
		committeeMD.Committers = make([]int32, len(prevCommitteeMD.Committers))
		copy(committeeMD.Committers, prevCommitteeMD.Committers)
		committeeMD.CommitteeShiftAt = prevCommitteeMD.CommitteeShiftAt
		committeeMD.FinalStateIndex = prevCommitteeMD.FinalStateIndex

		// If we shifted committees in the previous block, this is a new committee.
		// So wipe out all the previous committers.
		if committeeMD.CommitteeShiftAt == blockNum-1 {
			committeeMD.Committers = nil
			logger.Debugf("This is a new committee with GenesisConfigAt(%d), CommitteeShiftAt(%d), FinalStateIndex(%d)",
				committeeMD.GenesisConfigAt, committeeMD.CommitteeShiftAt, committeeMD.FinalStateIndex)
		} else {
			logger.Debugf("Transferring previous committee metadata GenesisConfigAt(%d), Committers(%v), CommitteeShiftAt(%d), FinalStateIndex(%d)",
				committeeMD.GenesisConfigAt, committeeMD.Committers, committeeMD.CommitteeShiftAt, committeeMD.FinalStateIndex)
		}
	}

	// We are committing
	if len(commitment) > 0 && committeeMD.ShouldCommit(id, expectedCommitters, logger) {
		committeeMD.State = newState
		committeeMD.Committers = append(committeeMD.Committers, id)
		logger.Debugf("A commit has occurred, state has increased from %d to %d bytes", prevStateSize, len(committeeMD.State))
		logger.Debugf("Setting state to %s", base64.StdEncoding.EncodeToString(newState))
		if len(committeeMD.Committers) == expectedCommitters {
			committeeMD.FinalStateIndex = blockNum
			logger.Debugf("Final state index changed from %d to %d because this is the last commit",
				prevCommitteeMD.FinalStateIndex, committeeMD.FinalStateIndex)
		}
	}

	lastIndex := committeeMD.FinalStateIndex
	if committeeMD.CommitteeShiftAt > lastIndex {
		lastIndex = committeeMD.CommitteeShiftAt
	}

	// This might be the last block of the committee, so we need to prepare for the committee change.
	// We encode the block number where the committee ends, and the committee itself at that point.
	// This, alongside the FinalStateIndex and reconstruction shares collected from the signatures
	// at the block commit, is enough information for the committee selection library deduce the next committee.
	if len(committeeMD.Committers) == expectedCommitters && lastIndex > 0 && blockNum-lastIndex > int64(committeeMinimumLifespan) {
		committeeMD.CommitteeShiftAt = blockNum
		committeeMD.CommitteeAtShift = currentCommittee
		logger.Debugf("This block ends the committee, setting CommitteeShiftAt to be %d with committee of %v",
			committeeMD.CommitteeShiftAt, committeeMD.CommitteeAtShift.IDs())
	}

	return committeeMD
}

type CachingLedger struct {
	lock      sync.RWMutex
	initcache sync.Once
	Ledger    Ledger
	cache     map[uint64]*cacheEntry
}

type cacheEntry struct {
	block    *common.Block
	lastUsed time.Time
}

func (c *CachingLedger) Height() uint64 {
	return c.Ledger.Height()
}

func (c *CachingLedger) Block(seq uint64) *common.Block {
	block := c.lookup(seq)
	if block != nil {
		return block
	}

	block = c.Ledger.Block(seq)

	defer c.shrinkIfNeeded()

	c.lock.Lock()
	defer c.lock.Unlock()

	c.cache[seq] = &cacheEntry{
		block:    block,
		lastUsed: time.Now(),
	}
	return block
}

func (c *CachingLedger) lookup(seq uint64) *common.Block {
	c.initcache.Do(func() {
		cache := make(map[uint64]*cacheEntry)
		c.lock.Lock()
		c.cache = cache
		c.lock.Unlock()
	})
	c.lock.RLock()
	entry, exists := c.cache[seq]
	c.lock.RUnlock()

	if !exists {
		return nil
	}

	c.lock.Lock()
	entry.lastUsed = time.Now()
	c.cache[seq] = entry
	c.lock.Unlock()

	return entry.block
}

func (c *CachingLedger) shrinkIfNeeded() {
	c.lock.RLock()
	shrinkNeeded := len(c.cache) >= 5
	c.lock.RUnlock()
	if !shrinkNeeded {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	for len(c.cache) > 4 {
		c.evictOldest()
	}
}

func (c *CachingLedger) evictOldest() {
	var oldestTime time.Time
	var oldestSeqUsed uint64
	// Get first entry to set the minimum
	for seq, entry := range c.cache {
		oldestTime = entry.lastUsed
		oldestSeqUsed = seq
		break
	}

	// Find the minimum
	for seq, entry := range c.cache {
		if entry.lastUsed.Before(oldestTime) {
			oldestTime = entry.lastUsed
			oldestSeqUsed = seq
		}
	}

	// Remove the minimum
	delete(c.cache, oldestSeqUsed)
}
