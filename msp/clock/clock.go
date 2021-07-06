package clock

import (
	"errors"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/flogging"
)

var (
	mutex  sync.Mutex
	clocks map[string]*ChannelSyncedClock = make(map[string]*ChannelSyncedClock)
	logger *flogging.FabricLogger         = flogging.MustGetLogger("channelclock")
)

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

func (c *ChannelSyncedClock) SyncedTime() (*time.Time, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.syncedTime == nil {
		logger.Infof("time has not been synced yet, channelID: %s", c.channelID)
		return nil, errors.New("time has not been synced yet")
	}
	return c.syncedTime, nil
}

func (c *ChannelSyncedClock) SyncWithBlock(block *common.Block) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if block.Header.Number == 0 {
		// it is genesis block, time has not been synced yet
		return nil
	}

	if block.Header.Timestamp == 0 {
		return errors.New("timestamp should not be 0 for not genesis block")
	}

	time := time.Unix(0, int64(block.Header.Timestamp))
	if c.syncedTime != nil && time.Before(*c.syncedTime) {
		return errors.New("current synced time is before last synced time")
	}
	c.syncedTime = &time
	logger.Infof("current synced time: %v, channelID: %s", time, c.channelID)
	return nil
}
