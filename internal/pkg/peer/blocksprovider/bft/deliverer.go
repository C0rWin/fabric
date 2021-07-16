package bft

import (
	"math"
	"sync"
	"time"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/internal/pkg/peer/blocksprovider"
	"github.com/pkg/errors"
)

type Deliverer struct {
	ChannelID           string
	Gossip              blocksprovider.GossipServiceAdapter
	Ledger              blocksprovider.LedgerInfo
	BlockHeaderVerifier blocksprovider.BlockHeaderVerifier
	Dialer              blocksprovider.Dialer
	Orderers            blocksprovider.OrdererConnectionSource
	DoneC               chan struct{}
	Signer              identity.SignerSerializer
	DeliverStreamer     blocksprovider.DeliverStreamer
	Logger              *flogging.FabricLogger
	YieldLeadership     bool

	MaxRetryDelay     time.Duration
	InitialRetryDelay time.Duration
	MaxRetryDuration  time.Duration

	// TLSCertHash should be nil when TLS is not enabled
	TLSCertHash []byte // util.ComputeSHA256(b.credSupport.GetClientCertificate().Certificate[0])

	sleeper sleeper

	// The block censorship timeout. A block censorship suspicion is declared if more than f header receivers are
	// ahead of the block receiver for a period larger than this timeout.
	BlockCensorshipTimeout time.Duration

	blocksDeliverer      *BlocksDeliverer
	blocksDelivererIndex int
	headersDeliverers    map[string]*HeadersDeliverer

	mutex    sync.Mutex
	stopFlag bool
}

func NewDeliverer(
	channelID string,
	gossip blocksprovider.GossipServiceAdapter,
	ledger blocksprovider.LedgerInfo,
	blockHeaderVerifier blocksprovider.BlockHeaderVerifier,
	dialer blocksprovider.Dialer,
	orderers blocksprovider.OrdererConnectionSource,
	doneC chan struct{},
	signer identity.SignerSerializer,
	deliverStreamer blocksprovider.DeliverStreamer,
	logger *flogging.FabricLogger,
	yieldLeadership bool,
	maxRetryDelay time.Duration,
	initialRetryDelay time.Duration,
	maxRetryDuration time.Duration,
	blockCensorshipTimeout time.Duration,
) *Deliverer {
	logger.Infof("[%s] Created BFT Delivery Client", channelID)
	return &Deliverer{
		ChannelID:              channelID,
		Gossip:                 gossip,
		Ledger:                 ledger,
		BlockHeaderVerifier:    blockHeaderVerifier,
		Dialer:                 dialer,
		Orderers:               orderers,
		DoneC:                  doneC,
		Signer:                 signer,
		DeliverStreamer:        deliverStreamer,
		Logger:                 logger,
		YieldLeadership:        yieldLeadership,
		MaxRetryDelay:          maxRetryDelay,
		InitialRetryDelay:      initialRetryDelay,
		MaxRetryDuration:       maxRetryDuration,
		BlockCensorshipTimeout: blockCensorshipTimeout,

		headersDeliverers:    make(map[string]*HeadersDeliverer),
		blocksDelivererIndex: -1,
	}
}

func (d *Deliverer) DeliverBlocks() {
	var num uint64
	num, err := d.Ledger.LedgerHeight()
	if err != nil {
		d.Logger.Debugf("[%s] Cannot access ledger height: %v", d.ChannelID, err)
		return
	}

	d.Logger.Debugf("[%s] Starting monitor routine; Initial ledger height: %d", d.ChannelID, num)
	go d.monitor()

	failureCounter := 0
	totalDuration := time.Duration(0)

	// InitialRetryDelay * backoffExponentBase^n > MaxRetryDelay
	// backoffExponentBase^n > MaxRetryDelay / InitialRetryDelay
	// n * log(backoffExponentBase) > log(MaxRetryDelay / InitialRetryDelay)
	// n > log(MaxRetryDelay / InitialRetryDelay) / log(backoffExponentBase)
	maxFailures := int(math.Log(float64(d.MaxRetryDelay)/float64(d.InitialRetryDelay)) / math.Log(backoffExponentBase))

	for !d.shouldStop() {
		select {
		case <-d.DoneC:
			return
		default:
		}

		if failureCounter > 0 {
			var sleepDuration time.Duration
			if failureCounter-1 > maxFailures {
				sleepDuration = d.MaxRetryDelay
			} else {
				sleepDuration = time.Duration(math.Pow(1.2, float64(failureCounter-1))*100) * time.Millisecond
			}
			totalDuration += sleepDuration
			if totalDuration > d.MaxRetryDuration {
				if d.YieldLeadership {
					d.Logger.Warningf("attempted to retry block delivery for more than %v, giving up", d.MaxRetryDuration)
					return
				}
				d.Logger.Warningf("peer is a static leader, ignoring peer.deliveryclient.reconnectTotalTimeThreshold")
			}
			d.sleeper.Sleep(sleepDuration, d.DoneC)
		}

		_, err := d.assignDeliverers()
		if err != nil {
			d.Logger.Debugf("[%s] Cannot assign deliverers: %v", d.ChannelID, err)
			failureCounter++
			continue
		}

		d.launchHeadersDeliverers()

		criticalError, endpointRefreshed := d.blocksDeliverer.DeliverBlocks(&failureCounter)
		if criticalError {
			return
		}

		if endpointRefreshed {
			for _, headersDeliverer := range d.headersDeliverers {
				headersDeliverer.Stop()
			}
		}
	}
}

// Stop stops blocks delivery provider
func (d *Deliverer) Stop() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// this select is not race-safe, but it prevents a panic
	// for careless callers multiply invoking stop
	select {
	case <-d.DoneC:
	default:
		if d.blocksDeliverer != nil {
			d.blocksDeliverer.Stop()
		}

		for _, headersDeliverer := range d.headersDeliverers {
			headersDeliverer.Stop()
		}
		d.stopFlag = true
		close(d.DoneC)
	}
}

// Check block reception progress relative to header reception progress.
// If the orderer associated with the block receiver is suspected of censorship, replace it with another orderer.
func (d *Deliverer) monitor() {
	d.Logger.Debugf("[%s] Entry", d.ChannelID)

	ticker := time.NewTicker(d.BlockCensorshipTimeout / 100)
	for !d.shouldStop() {
		if suspicion := d.detectBlockCensorship(); suspicion {
			d.closeBlocksDeliverer()
		}

		select {
		case <-ticker.C:
		case <-d.DoneC:
		}
	}
	ticker.Stop()

	d.Logger.Debugf("[%s] Exit", d.ChannelID)
}

func (d *Deliverer) detectBlockCensorship() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.blocksDeliverer == nil {
		return false
	}

	var err error
	lastBlockNum, lastBlockTime, err := d.blocksDeliverer.LastBlockNum()
	if err != nil {
		return false
	}

	now := time.Now()
	suspicionThreshold := lastBlockTime.Add(d.BlockCensorshipTimeout)
	if now.Before(suspicionThreshold) {
		return false
	}

	var numAhead int
	for ep, hRcv := range d.headersDeliverers {
		blockNum, _, err := hRcv.LastBlockNum()
		if err != nil {
			continue
		}
		if blockNum >= lastBlockNum+1 {
			d.Logger.Infof("[%s] header receiver: %s, is ahead of block receiver, headr-rcv=%d, block-rcv=%d", d.ChannelID, ep, blockNum, lastBlockNum)
			numAhead++
		}
	}

	endpoints, err := d.Orderers.AllEndpoints()
	if err != nil {
		d.Logger.Warnf("[%s] failed to get ordrerer endpoints: %v", d.ChannelID, err)
	}

	numEP := uint64(len(endpoints))
	_, f := computeQuorum(numEP)
	if numAhead > f {
		d.Logger.Warnf("[%s] suspected block censorship: %d header receivers are ahead of block receiver, out of %d endpoints",
			d.ChannelID, numAhead, numEP)
		return true
	}

	return false
}

func computeQuorum(N uint64) (Q int, F int) {
	F = int((int(N) - 1) / 3)
	Q = int(math.Ceil((float64(N) + float64(F) + 1) / 2.0))
	return
}

func (d *Deliverer) closeBlocksDeliverer() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.blocksDeliverer != nil {
		d.blocksDeliverer.Stop()
		d.blocksDeliverer = nil
	}
}

func (d *Deliverer) shouldStop() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.stopFlag
}

// (re)-assign a block delivery client and header delivery clients
func (d *Deliverer) assignDeliverers() (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	endpoints, err := d.Orderers.AllEndpoints()
	if err != nil {
		d.Logger.Infof("[%s] Cannot access orderers endpoints: %v", d.ChannelID, err)
		return 0, err
	}

	if len(endpoints) == 0 {
		d.Logger.Infof("[%s] no endpoints", d.ChannelID)
		return 0, errors.New("no orderer endpoints")
	}

	d.blocksDelivererIndex = (d.blocksDelivererIndex + 1) % len(endpoints)

	// init BlocksDeliverer and HeadersDeliverers
	d.blocksDeliverer = &BlocksDeliverer{
		ChannelID:       d.ChannelID,
		Gossip:          d.Gossip,
		Ledger:          d.Ledger,
		BlockVerifier:   d.BlockHeaderVerifier,
		Dialer:          d.Dialer,
		Endpoint:        endpoints[d.blocksDelivererIndex],
		DoneC:           make(chan struct{}),
		Signer:          d.Signer,
		DeliverStreamer: d.DeliverStreamer,
		Logger:          flogging.MustGetLogger("peer.blocksdeliverer").With("channel", d.ChannelID),
	}
	d.Logger.Infof("[%s] Initialized a block deliverer to endpoint: %v", d.ChannelID, d.blocksDeliverer.Endpoint.Address)

	unusedHeadersDeliverers := make(map[string]*HeadersDeliverer)
	for k, v := range d.headersDeliverers {
		unusedHeadersDeliverers[k] = v
	}

	for i := 0; i < len(endpoints); i++ {
		if i == d.blocksDelivererIndex {
			continue
		}

		delete(unusedHeadersDeliverers, endpoints[i].Address)

		_, exists := d.headersDeliverers[endpoints[i].Address]
		if exists && d.headersDeliverers[endpoints[i].Address].isStarted() {
			continue
		}

		headersDeliverer := &HeadersDeliverer{
			ChannelID:         d.ChannelID,
			Gossip:            d.Gossip,
			Ledger:            d.Ledger,
			HeaderVerifier:    d.BlockHeaderVerifier,
			Dialer:            d.Dialer,
			Endpoint:          endpoints[i],
			DoneC:             make(chan struct{}),
			Signer:            d.Signer,
			DeliverStreamer:   d.DeliverStreamer,
			Logger:            flogging.MustGetLogger("peer.headersdeliverer").With("channel", d.ChannelID),
			MaxRetryDelay:     d.MaxRetryDelay,
			InitialRetryDelay: 100 * time.Millisecond,
		}

		d.headersDeliverers[endpoints[i].Address] = headersDeliverer

		d.Logger.Infof("[%s] Initialized a header deliverer to endpoint: %v", d.ChannelID, headersDeliverer.Endpoint.Address)
	}

	for ep, headerDeliverer := range unusedHeadersDeliverers {
		headerDeliverer.Stop()
		delete(d.headersDeliverers, ep)
	}

	return len(endpoints), nil
}

func (d *Deliverer) launchHeadersDeliverers() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var launched int
	for ep, hRcv := range d.headersDeliverers {
		if !hRcv.isStarted() {
			d.Logger.Infof("[%s] launching a header receiver to endpoint: %s", d.ChannelID, ep)
			launched++
			go hRcv.DeliverHeaders()
		}
	}

	d.Logger.Infof("[%s] header receivers: launched=%d, total running=%d ", d.ChannelID, launched, len(d.headersDeliverers))
}
