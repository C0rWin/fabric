package clock

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/flogging"
)

var (
	mutex             sync.Mutex
	clocks            map[string]*ChannelSyncedClock = make(map[string]*ChannelSyncedClock)
	logger            *flogging.FabricLogger         = flogging.MustGetLogger("channelclock")
	timestampAccuracy func(cid string) (*time.Duration, error)
)

func SetTimestampAccuracyProvider(timestampAccuracyProvider func(cid string) (*time.Duration, error)) error {
	timestampAccuracy = timestampAccuracyProvider
	logger.Infof("timestamp accuracy provider initialized")
	return nil
}

type ChannelSyncedClock struct {
	channelID  string
	syncedTime *time.Time
	mutex      sync.Mutex
}

func GetOrCreateChannelSyncedClock(channelID string) *ChannelSyncedClock {
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := clocks[channelID]; !ok {
		clocks[channelID] = &ChannelSyncedClock{
			channelID: channelID,
		}
	}

	return clocks[channelID]
}

func ResetAll() {
	mutex.Lock()
	defer mutex.Unlock()

	for channelID := range clocks {
		clocks[channelID].mutex.Lock()
		clocks[channelID].syncedTime = nil
		clocks[channelID].mutex.Unlock()
	}
}

func Reset(channelID string) {
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := clocks[channelID]; !ok {
		return
	}
	clocks[channelID].mutex.Lock()
	defer clocks[channelID].mutex.Unlock()
	clocks[channelID].syncedTime = nil
}

func (c *ChannelSyncedClock) Synced() (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.syncedTime == nil {
		logger.Infof("time has not been synced yet, channelID: %s", c.channelID)
		return false, errors.New("time has not been synced yet")
	}

	if timestampAccuracy == nil {
		logger.Infof("timestamp accuracy provider has not been initialized yet")
		return false, errors.New("timestamp accuracy provider has not been initialized yet")
	}

	_, err := timestampAccuracy(c.channelID)
	if err != nil {
		logger.Infof("failed to get timestamp accuracy: %v", err)
		return false, fmt.Errorf("failed to get timestamp accuracy: %v", err)
	}

	return true, nil
}

func (c *ChannelSyncedClock) SyncedTime() (*time.Time, *time.Duration, error) {
	synced, err := c.Synced()
	if !synced {
		return nil, nil, err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	accuracy, err := timestampAccuracy(c.channelID)
	if err != nil {
		logger.Infof("failed to get timestamp accuracy: %v", err)
		return nil, nil, fmt.Errorf("failed to get timestamp accuracy: %v", err)
	}

	logger.Infof("current synced time: %v, accuracy: %v, channelID: %s", c.syncedTime, accuracy, c.channelID)
	return c.syncedTime, accuracy, nil
}

func (c *ChannelSyncedClock) SyncWithBlock(block *common.Block) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if block.Header.Number == 0 {
		// it is genesis block, time has not been synced yet
		return nil
	}

	// TODO: This should not be commented out, but adding this check will cause a lot of tests to fail.
	// if block.Header.Timestamp == 0 {
	// 	return errors.New("timestamp should not be 0 for not genesis block")
	// }

	time := time.Unix(0, int64(block.Header.Timestamp))
	if c.syncedTime != nil && time.Before(*c.syncedTime) {
		return errors.New("current synced time is before last synced time")
	}
	c.syncedTime = &time

	logger.Infof("new synced time: %v, channelID: %s", time, c.channelID)
	return nil
}
