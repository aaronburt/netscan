package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/config"
)

type Compactor struct {
	cfg config.Config
}

func NewCompactor(cfg config.Config) *Compactor {
	return &Compactor{cfg: cfg}
}

func (c *Compactor) Compact(db *sql.DB, now time.Time) error {
	partitions, err := c.findRawPartitions(db)
	if err != nil {
		return err
	}

	rawRetentionDays := c.cfg.Retention.RawPartitions
	if rawRetentionDays < 1 {
		rawRetentionDays = 1
	}

	cutoffDay := now.AddDate(0, 0, -rawRetentionDays)
	cutoffStr := cutoffDay.Format("20060102")

	events, err := c.getActiveAndRecentEvents(db, now)
	if err != nil {
		return err
	}

	for _, part := range partitions {
		dayStr := strings.TrimPrefix(part, "samples_")
		if len(dayStr) != 8 {
			continue
		}

		if dayStr >= cutoffStr {
			continue
		}

		partTime, err := time.Parse("20060102", dayStr)
		if err != nil {
			continue
		}
		partDayStart := partTime.UnixMilli()
		partDayEnd := partTime.Add(24 * time.Hour).UnixMilli()

		skipDrop := false
		for _, ev := range events {
			if ev.isRecentOrOpen(now) && ev.overlaps(partDayStart, partDayEnd) {
				skipDrop = true
				break
			}
		}
		if skipDrop {
			continue
		}

		if err := c.copyEventWindowsAndDrop(db, part, partDayStart, partDayEnd); err != nil {
			return err
		}
	}

	if err := c.expireOldData(db, now); err != nil {
		return err
	}

	_, _ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	_, _ = db.Exec("PRAGMA incremental_vacuum;")

	return nil
}

func (c *Compactor) findRawPartitions(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'samples_20%' ORDER BY name ASC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, name)
		}
	}
	return names, nil
}

type eventWindow struct {
	startMS int64
	endMS   int64
	isOpen  bool
}

func (w eventWindow) overlaps(dayStart, dayEnd int64) bool {
	return w.startMS <= dayEnd && w.endMS >= dayStart
}

func (w eventWindow) isRecentOrOpen(now time.Time) bool {
	if w.isOpen {
		return true
	}
	twoMinAgo := now.Add(-2 * time.Minute).UnixMilli()
	return w.endMS >= twoMinAgo
}

func (c *Compactor) getActiveAndRecentEvents(db *sql.DB, now time.Time) ([]eventWindow, error) {
	query := `SELECT start_ms, end_ms, kind FROM events WHERE end_ms IS NULL OR end_ms >= ?;`
	threeDaysAgo := now.AddDate(0, 0, -3).UnixMilli()

	rows, err := db.Query(query, threeDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []eventWindow
	for rows.Next() {
		var startMS int64
		var endMS sql.NullInt64
		var kind string
		if err := rows.Scan(&startMS, &endMS, &kind); err != nil {
			continue
		}

		marginMS := int64(30000)
		if kind == "blip" || kind == "latency" {
			marginMS = 15000
		}

		win := eventWindow{
			startMS: startMS - marginMS,
		}
		if endMS.Valid {
			win.endMS = endMS.Int64 + marginMS
			win.isOpen = false
		} else {
			win.endMS = now.UnixMilli() + marginMS
			win.isOpen = true
		}
		windows = append(windows, win)
	}

	return windows, nil
}

func (c *Compactor) copyEventWindowsAndDrop(db *sql.DB, tableName string, dayStart, dayEnd int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	queryEvents := `SELECT start_ms, end_ms, kind FROM events WHERE (end_ms IS NULL OR end_ms >= ?) AND start_ms <= ?;`
	rows, err := tx.Query(queryEvents, dayStart-30000, dayEnd+30000)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var startMS int64
			var endMS sql.NullInt64
			var kind string
			if err := rows.Scan(&startMS, &endMS, &kind); err != nil {
				continue
			}
			margin := int64(30000)
			if kind == "blip" || kind == "latency" {
				margin = 15000
			}
			winStart := startMS - margin
			winEnd := time.Now().UTC().UnixMilli()
			if endMS.Valid {
				winEnd = endMS.Int64 + margin
			}

			copyQuery := fmt.Sprintf(`INSERT OR IGNORE INTO event_samples (
				ts_ms, target_id, reached, ok, rtt_us, err, flags, dns_us, tcp_us, tls_us, ttfb_us, status, err_text
			) SELECT ts_ms, target_id, reached, ok, rtt_us, err, flags, dns_us, tcp_us, tls_us, ttfb_us, status, err_text
			FROM %s WHERE ts_ms >= ? AND ts_ms <= ?;`, tableName)
			_, _ = tx.Exec(copyQuery, winStart, winEnd)
		}
		rows.Close()
	}

	dropQuery := fmt.Sprintf(`DROP TABLE IF EXISTS %s;`, tableName)
	if _, err := tx.Exec(dropQuery); err != nil {
		return err
	}

	return tx.Commit()
}

func (c *Compactor) expireOldData(db *sql.DB, now time.Time) error {
	eventWindowDays := c.cfg.Retention.EventWindowDays
	if eventWindowDays < 7 {
		eventWindowDays = 7
	}
	cutoffSamples := now.AddDate(0, 0, -eventWindowDays).UnixMilli()
	if err := deleteBatch(db, "event_samples", "ts_ms < ?", cutoffSamples); err != nil {
		return err
	}

	rollupDays := c.cfg.Retention.RollupDays
	if rollupDays < 7 {
		rollupDays = 7
	}
	cutoffRollups := now.AddDate(0, 0, -rollupDays).UnixMilli()
	if err := deleteBatch(db, "rollups_1m", "bucket_ms < ?", cutoffRollups); err != nil {
		return err
	}

	eventDays := c.cfg.Retention.EventDays
	if eventDays < 30 {
		eventDays = 30
	}
	cutoffEvents := now.AddDate(0, 0, -eventDays).UnixMilli()
	if err := deleteBatch(db, "events", "start_ms < ?", cutoffEvents); err != nil {
		return err
	}
	if err := deleteBatch(db, "system_events", "ts_ms < ?", cutoffEvents); err != nil {
		return err
	}
	if err := deleteBatch(db, "coverage", "heartbeat_ms < ?", cutoffEvents); err != nil {
		return err
	}

	return nil
}

func deleteBatch(db *sql.DB, table string, where string, args ...any) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE %s;", table, where)
	_, err := db.Exec(query, args...)
	return err
}
