/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"sync"
	"sync/atomic"
	"time"
)

type MonitorLogger interface {
	Infof(template string, args ...interface{})
	Debugf(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Panicf(template string, args ...interface{})
}

// Role indicates if this node sends or receives heartbeats
type Role bool

// A node could either be a sender or a receiver
const (
	HeartbeatSender   Role = false
	HeartbeatReceiver Role = true
)

//go:generate mockery -dir . -name MessageSender -case underscore -output mocks

type MessageSender interface {
	SendHeartbeat(dest uint64)
}

type HeartbeatMonitor struct {
	messageSender     MessageSender
	scheduler         <-chan time.Time
	inc               chan uint64
	role              Role
	senders           []uint64
	receivers         []uint64
	lastReceivedTimes []time.Time
	hbTimeout         time.Duration
	hbCount           uint64
	lastTick          time.Time
	lastHeartbeat     time.Time
	logger            MonitorLogger
	stopChan          chan struct{}
	running           sync.WaitGroup
	monitorLock       sync.RWMutex
}

// NewHeartbeatMonitor creates a new HeartbeatMonitor
func NewHeartbeatMonitor(messageSender MessageSender, scheduler <-chan time.Time, logger MonitorLogger, heartbeatTimeout time.Duration, heartbeatCount uint64, role Role, senders []uint64, receivers []uint64) *HeartbeatMonitor {
	hm := &HeartbeatMonitor{
		stopChan:          make(chan struct{}),
		inc:               make(chan uint64),
		messageSender:     messageSender,
		scheduler:         scheduler,
		logger:            logger,
		hbTimeout:         heartbeatTimeout,
		hbCount:           heartbeatCount,
		role:              role,
		senders:           senders,
		receivers:         receivers,
		lastReceivedTimes: make([]time.Time, len(senders)),
	}
	return hm
}

// Start starts the heartbeat monitor
func (hm *HeartbeatMonitor) Start() {
	hm.running.Add(1)
	if hm.role == HeartbeatReceiver {
		go hm.runReceiver()
	} else {
		go hm.runSender()
	}
}

// Close stops the heartbeat monitor
func (hm *HeartbeatMonitor) Close() {
	if hm.closed() {
		return
	}
	defer hm.running.Wait()
	close(hm.stopChan)
}

func (hm *HeartbeatMonitor) closed() bool {
	select {
	case <-hm.stopChan:
		return true
	default:
		return false
	}
}

func (hm *HeartbeatMonitor) runReceiver() {
	defer hm.running.Done()
	for {
		select {
		case <-hm.stopChan:
			return
		case sender := <-hm.inc:
			hm.processHeartbeat(sender)
		case now := <-hm.scheduler:
			hm.tick(now)
		}
	}
}

func (hm *HeartbeatMonitor) runSender() {
	defer hm.running.Done()
	for {
		select {
		case <-hm.stopChan:
			return
		case now := <-hm.scheduler:
			hm.tick(now)
			hm.checkIfTimeToSend()
		}
	}
}

func (hm *HeartbeatMonitor) tick(now time.Time) {
	hm.monitorLock.Lock()
	defer hm.monitorLock.Unlock()
	hm.lastTick = now
}

func (hm *HeartbeatMonitor) checkIfTimeToSend() {
	if hm.lastHeartbeat.IsZero() {
		hm.lastHeartbeat = hm.lastTick
	}
	if hm.lastTick.Sub(hm.lastHeartbeat)*time.Duration(hm.hbCount) < hm.hbTimeout {
		return
	}
	for _, n := range hm.receivers {
		hm.sendHeartbeat(n)
	}
	hm.lastHeartbeat = hm.lastTick
}

func (hm *HeartbeatMonitor) sendHeartbeat(targetID uint64) {
	hm.logger.Debugf("Sending heartbeat to node %d", targetID)
	hm.messageSender.SendHeartbeat(targetID)
}

// ProcessHeartbeat processes the heartbeat from the sender
func (hm *HeartbeatMonitor) ProcessHeartbeat(sender uint64) {
	select {
	case hm.inc <- sender:
	case <-hm.stopChan:
	}
}

func (hm *HeartbeatMonitor) processHeartbeat(sender uint64) {
	hm.logger.Debugf("Processing heartbeat from node %d", sender)
	hm.monitorLock.Lock()
	defer hm.monitorLock.Unlock()
	for i, s := range hm.senders {
		if s == sender {
			hm.lastReceivedTimes[i] = hm.lastTick
			return
		}
	}
	hm.logger.Warnf("Node %d is not a heartbeat sender", sender)
}

// GetSuspects returns a list of all senders that did not send a heartbeat in a long time
func (hm *HeartbeatMonitor) GetSuspects() []uint64 {
	hm.monitorLock.RLock()
	defer hm.monitorLock.RUnlock()
	suspects := make([]uint64, 0)
	if hm.role == HeartbeatSender {
		return suspects
	}
	for i, lastHb := range hm.lastReceivedTimes {
		if lastHb.IsZero() {
			hm.logger.Debugf("Node %d did not send a heartbeat yet and therefore a suspect", hm.senders[i])
			suspects = append(suspects, hm.senders[i])
			continue
		}
		if hm.lastTick.Sub(lastHb) >= hm.hbTimeout {
			hm.logger.Debugf("Node %d did not send a heartbeat in a long time and therefore a suspect", hm.senders[i])
			suspects = append(suspects, hm.senders[i])
		}
	}
	hm.logger.Infof("The suspects are %v", suspects)
	return suspects
}

type AtomicHeartBeatMonitor struct {
	hbm atomic.Value
}

func (ahbm *AtomicHeartBeatMonitor) Set(hbm *HeartbeatMonitor) {
	prev := ahbm.hbm.Load()
	if prev != nil {
		prev.(*HeartbeatMonitor).Close()
	}
	ahbm.hbm.Store(hbm)
}

func (ahbm *AtomicHeartBeatMonitor) GetSuspects() []uint64 {
	hbm := ahbm.hbm.Load()
	if hbm != nil {
		return hbm.(*HeartbeatMonitor).GetSuspects()
	}
	return nil
}

func (ahbm *AtomicHeartBeatMonitor) ProcessHeartbeat(sender uint64) {
	hbm := ahbm.hbm.Load()
	if hbm != nil {
		hbm.(*HeartbeatMonitor).ProcessHeartbeat(sender)
	}
}

func (ahbm *AtomicHeartBeatMonitor) Close() {
	hbm := ahbm.hbm.Load()
	if hbm != nil {
		hbm.(*HeartbeatMonitor).Close()
	}
}

func (ahbm *AtomicHeartBeatMonitor) Start() {
	hbm := ahbm.hbm.Load()
	if hbm != nil {
		hbm.(*HeartbeatMonitor).Start()
	}
}
