package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
)

type writeItemType int

const (
	writeItemSample writeItemType = iota
	writeItemEvent
	writeItemSysEvent
	writeItemCoverage
	writeItemTarget
	writeItemNetwork
)

type writeItem struct {
	itemType writeItemType
	sample   probe.ProbeResult
	event    detector.Event
	sysEvent netenv.SystemEvent
	network  NetworkRecord
	target   probe.Target
	coverage CoverageRecord
}

type NetworkRecord struct {
	ID          int64
	Fingerprint string
	GatewayIP   string
	GatewayMAC  string
	SSID        string
	Label       string
	FirstSeenMS int64
	LastSeenMS  int64
}

type CoverageRecord struct {
	ID          int64
	NetworkID   int64
	StartMS     int64
	HeartbeatMS int64
	EndMS       *int64
	EndReason   string
}

type rollupBucketKey struct {
	bucketMS int64
	targetID int
}

type rollupAccumulator struct {
	sent    int
	reached int
	ok      int
	flagged int
	rtts    []int64
}

type StoreWriter struct {
	db              *sql.DB
	cfg             config.Config
	inCh            chan writeItem
	flushReqCh      chan chan struct{}
	stopped         chan struct{}
	stopOnce        sync.Once
	droppedSamples  atomic.Int64
	lastDropLogTime time.Time
	knownPartitions map[string]bool
	lock            sync.Mutex
	rollups         map[rollupBucketKey]*rollupAccumulator
	compactor       *Compactor
}

func NewStoreWriter(db *sql.DB, cfg config.Config) *StoreWriter {
	return &StoreWriter{
		db:              db,
		cfg:             cfg,
		inCh:            make(chan writeItem, 8192),
		flushReqCh:      make(chan chan struct{}, 1),
		stopped:         make(chan struct{}),
		knownPartitions: make(map[string]bool),
		rollups:         make(map[rollupBucketKey]*rollupAccumulator),
		compactor:       NewCompactor(cfg),
	}
}

// FlushSync blocks until everything queued so far is written. It returns
// straight away once Run has stopped, because Run flushes on its way out.
func (w *StoreWriter) FlushSync() {
	done := make(chan struct{})
	select {
	case w.flushReqCh <- done:
	case <-w.stopped:
		return
	}
	select {
	case <-done:
	case <-w.stopped:
	}
}

func (w *StoreWriter) ResetHistory() error {
	w.lock.Lock()
	defer w.lock.Unlock()

	for {
		select {
		case <-w.inCh:
		default:
			goto drained
		}
	}
drained:
	w.rollups = make(map[rollupBucketKey]*rollupAccumulator)

	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{
		"DELETE FROM events;",
		"DELETE FROM event_samples;",
		"DELETE FROM rollups_1m;",
		"DELETE FROM system_events;",
		"DELETE FROM coverage;",
	}
	for _, q := range tables {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}

	rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'samples_%';")
	if err == nil {
		var partTables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				partTables = append(partTables, name)
			}
		}
		_ = rows.Close()

		for _, pt := range partTables {
			_, _ = tx.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s;", pt))
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	w.knownPartitions = make(map[string]bool)
	_, _ = w.db.Exec("PRAGMA incremental_vacuum;")
	return nil
}

func (w *StoreWriter) QueueSample(res probe.ProbeResult) {
	item := writeItem{
		itemType: writeItemSample,
		sample:   res,
	}
	select {
	case w.inCh <- item:
	default:
		w.droppedSamples.Add(1)
		w.dropOldestAndQueue(item)
	}
}

func (w *StoreWriter) QueueEvent(evt detector.Event) {
	item := writeItem{
		itemType: writeItemEvent,
		event:    evt,
	}
	w.inCh <- item
}

func (w *StoreWriter) QueueSystemEvent(evt netenv.SystemEvent) {
	item := writeItem{
		itemType: writeItemSysEvent,
		sysEvent: evt,
	}
	w.inCh <- item
}

func (w *StoreWriter) QueueTarget(t probe.Target) {
	item := writeItem{
		itemType: writeItemTarget,
		target:   t,
	}
	w.inCh <- item
}

func (w *StoreWriter) QueueNetwork(net NetworkRecord) {
	item := writeItem{
		itemType: writeItemNetwork,
		network:  net,
	}
	w.inCh <- item
}

func (w *StoreWriter) QueueCoverage(cov CoverageRecord) {
	item := writeItem{
		itemType: writeItemCoverage,
		coverage: cov,
	}
	w.inCh <- item
}

func (w *StoreWriter) dropOldestAndQueue(item writeItem) {
	select {
	case old := <-w.inCh:
		if old.itemType != writeItemSample {
			w.inCh <- old
		}
	default:
	}

	select {
	case w.inCh <- item:
	default:
	}
}

func (w *StoreWriter) Run(ctx context.Context) error {
	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()

	compactTicker := time.NewTicker(1 * time.Hour)
	defer compactTicker.Stop()

	batch := make([]writeItem, 0, 500)

	for {
		select {
		case <-ctx.Done():
			w.drainAndFlush(batch)
			w.stopOnce.Do(func() { close(w.stopped) })
			return nil

		case item := <-w.inCh:
			batch = append(batch, item)
			if item.itemType == writeItemEvent || len(batch) >= 500 {
				w.flush(batch)
				batch = batch[:0]
			}

		case done := <-w.flushReqCh:
			w.drainAndFlush(batch)
			batch = batch[:0]
			close(done)

		case <-flushTicker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
			w.flushMatureRollups(time.Now().UTC())

		case <-compactTicker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
			w.compactor.Compact(w.db, time.Now().UTC())
		}
	}
}

func (w *StoreWriter) drainAndFlush(batch []writeItem) {
	for {
		select {
		case item := <-w.inCh:
			batch = append(batch, item)
			if len(batch) >= 500 {
				w.flush(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				w.flush(batch)
			}
			w.flushMatureRollups(time.Now().UTC().Add(1 * time.Minute))
			return
		}
	}
}

func (w *StoreWriter) flush(batch []writeItem) {
	if len(batch) == 0 {
		return
	}

	tx, err := w.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	sampleStmts := make(map[string]*sql.Stmt)
	defer func() {
		for _, stmt := range sampleStmts {
			_ = stmt.Close()
		}
	}()

	for _, item := range batch {
		switch item.itemType {
		case writeItemSample:
			w.writeSampleTx(tx, item.sample, sampleStmts)
			w.accumulateRollup(item.sample)
		case writeItemEvent:
			w.writeEventTx(tx, item.event)
		case writeItemSysEvent:
			w.writeSysEventTx(tx, item.sysEvent)
		case writeItemTarget:
			w.writeTargetTx(tx, item.target)
		case writeItemNetwork:
			w.writeNetworkTx(tx, item.network)
		case writeItemCoverage:
			w.writeCoverageTx(tx, item.coverage)
		}
	}

	_ = tx.Commit()
}

func (w *StoreWriter) writeSampleTx(tx *sql.Tx, s probe.ProbeResult, stmts map[string]*sql.Stmt) {
	t := time.UnixMilli(s.SendTimeUTC).UTC()
	tableName := PartitionTableName(t)

	w.lock.Lock()
	if !w.knownPartitions[tableName] {
		_ = EnsurePartitionTableTx(tx, tableName)
		w.knownPartitions[tableName] = true
	}
	w.lock.Unlock()

	stmt, ok := stmts[tableName]
	if !ok {
		query := fmt.Sprintf(`INSERT INTO %s (
			ts_ms, target_id, reached, ok, rtt_us, err, flags, dns_us, tcp_us, tls_us, ttfb_us, status, err_text
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`, tableName)
		var err error
		stmt, err = tx.Prepare(query)
		if err != nil {
			return
		}
		stmts[tableName] = stmt
	}

	reachedInt := 0
	if s.Reached {
		reachedInt = 1
	}
	okInt := 0
	if s.OK {
		okInt = 1
	}

	var errVal any
	if s.ErrCode != probe.ErrNone {
		errVal = int(s.ErrCode)
	}

	_, _ = stmt.Exec(
		s.SendTimeUTC,
		s.TargetID,
		reachedInt,
		okInt,
		s.RTTUS,
		errVal,
		s.Flags,
		s.DNSUS,
		s.TCPUS,
		s.TLSUS,
		s.TTFBUS,
		s.HTTPStatus,
		s.ErrText,
	)
}

func (w *StoreWriter) accumulateRollup(s probe.ProbeResult) {
	bucketMS := (s.SendTimeUTC / 60000) * 60000
	key := rollupBucketKey{
		bucketMS: bucketMS,
		targetID: s.TargetID,
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	acc, ok := w.rollups[key]
	if !ok {
		acc = &rollupAccumulator{
			rtts: make([]int64, 0, 120),
		}
		w.rollups[key] = acc
	}

	acc.sent++
	if s.Reached {
		acc.reached++
	}
	if s.OK {
		acc.ok++
		acc.rtts = append(acc.rtts, s.RTTUS)
	}
	if (s.Flags&probe.FlagLatency) != 0 || (s.Flags&probe.FlagSpike) != 0 {
		acc.flagged++
	}
}

func (w *StoreWriter) flushMatureRollups(now time.Time) {
	w.lock.Lock()
	currentBucket := (now.UnixMilli() / 60000) * 60000
	graceCutoff := currentBucket - 60000

	toFlush := make(map[rollupBucketKey]*rollupAccumulator)
	for k, acc := range w.rollups {
		if k.bucketMS <= graceCutoff {
			toFlush[k] = acc
			delete(w.rollups, k)
		}
	}
	w.lock.Unlock()

	if len(toFlush) == 0 {
		return
	}

	tx, err := w.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	query := `INSERT OR REPLACE INTO rollups_1m (
		bucket_ms, target_id, sent, reached, ok, flagged, min_us, p50_us, p95_us, max_us, jitter_us
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return
	}
	defer stmt.Close()

	for k, acc := range toFlush {
		minUS, p50US, p95US, maxUS, jitterUS := computeRollupMetrics(acc.rtts)
		_, _ = stmt.Exec(
			k.bucketMS,
			k.targetID,
			acc.sent,
			acc.reached,
			acc.ok,
			acc.flagged,
			minUS,
			p50US,
			p95US,
			maxUS,
			jitterUS,
		)
	}

	_ = tx.Commit()
}

func computeRollupMetrics(rtts []int64) (int64, int64, int64, int64, int64) {
	if len(rtts) == 0 {
		return 0, 0, 0, 0, 0
	}

	sorted := make([]int64, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	minUS := sorted[0]
	maxUS := sorted[len(sorted)-1]

	p50Idx := len(sorted) / 2
	p50US := sorted[p50Idx]

	p95Idx := int(float64(len(sorted)) * 0.95)
	if p95Idx >= len(sorted) {
		p95Idx = len(sorted) - 1
	}
	p95US := sorted[p95Idx]

	var totalDiff int64
	diffCount := 0
	for i := 1; i < len(rtts); i++ {
		diff := rtts[i] - rtts[i-1]
		if diff < 0 {
			diff = -diff
		}
		totalDiff += diff
		diffCount++
	}

	var jitterUS int64
	if diffCount > 0 {
		jitterUS = totalDiff / int64(diffCount)
	}

	return minUS, p50US, p95US, maxUS, jitterUS
}

func (w *StoreWriter) writeEventTx(tx *sql.Tx, e detector.Event) {
	query := `INSERT INTO events (
		id, kind, classification, network_id, start_ms, start_uncert_ms, end_ms, end_uncert_ms,
		duration_ms, layers_down, flags, gateway_ok_pct, isp_hop_ok_pct, context
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		end_ms = excluded.end_ms,
		end_uncert_ms = excluded.end_uncert_ms,
		duration_ms = excluded.duration_ms,
		classification = excluded.classification,
		layers_down = excluded.layers_down,
		flags = excluded.flags,
		gateway_ok_pct = excluded.gateway_ok_pct,
		isp_hop_ok_pct = excluded.isp_hop_ok_pct;`

	_, _ = tx.Exec(
		query,
		e.ID,
		string(e.Kind),
		string(e.Classification),
		e.NetworkID,
		e.StartMS,
		e.StartUncertMS,
		e.EndMS,
		e.EndUncertMS,
		e.DurationMS,
		e.LayersDown,
		e.Flags,
		e.GatewayOKPct,
		e.ISPHopOKPct,
		e.ContextJSON,
	)
}

func (w *StoreWriter) writeSysEventTx(tx *sql.Tx, se netenv.SystemEvent) {
	query := `INSERT INTO system_events (ts_ms, kind, detail) VALUES (?, ?, ?);`
	_, _ = tx.Exec(query, se.Timestamp, string(se.Kind), se.Detail)
}

func (w *StoreWriter) writeTargetTx(tx *sql.Tx, t probe.Target) {
	query := `INSERT INTO targets (id, layer, address, label, first_seen_ms)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(layer, address) DO UPDATE SET
			label = excluded.label;`
	_, _ = tx.Exec(query, t.ID, string(t.Layer), t.Address, t.Label, time.Now().UTC().UnixMilli())
}

func (w *StoreWriter) writeNetworkTx(tx *sql.Tx, n NetworkRecord) {
	query := `INSERT INTO networks (id, fingerprint, gateway_ip, gateway_mac, ssid, label, first_seen_ms, last_seen_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			last_seen_ms = excluded.last_seen_ms,
			gateway_ip = excluded.gateway_ip,
			gateway_mac = excluded.gateway_mac,
			ssid = excluded.ssid;`
	_, _ = tx.Exec(query, n.ID, n.Fingerprint, n.GatewayIP, n.GatewayMAC, n.SSID, n.Label, n.FirstSeenMS, n.LastSeenMS)
}

func (w *StoreWriter) writeCoverageTx(tx *sql.Tx, c CoverageRecord) {
	query := `INSERT INTO coverage (id, network_id, start_ms, heartbeat_ms, end_ms, end_reason)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			heartbeat_ms = excluded.heartbeat_ms,
			end_ms = excluded.end_ms,
			end_reason = excluded.end_reason;`
	_, _ = tx.Exec(query, c.ID, c.NetworkID, c.StartMS, c.HeartbeatMS, c.EndMS, c.EndReason)
}
