package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const SchemaVersion = "2"

func OpenDB(path string) (*sql.DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func QuickCheck(db *sql.DB) error {
	var res string
	row := db.QueryRow("PRAGMA quick_check;")
	if err := row.Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("database corrupted: %s", res)
	}
	return nil
}

func QuarantineCorruptDB(path string) error {
	ts := time.Now().UTC().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.corrupt-%s", path, ts)
	return os.Rename(path, backupPath)
}

func InitSchema(db *sql.DB) error {
	_, _ = db.Exec("PRAGMA auto_vacuum = INCREMENTAL;")

	queries := []string{
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS networks (
			id INTEGER PRIMARY KEY,
			fingerprint TEXT NOT NULL UNIQUE,
			gateway_ip TEXT,
			gateway_mac TEXT,
			ssid TEXT,
			label TEXT,
			first_seen_ms INTEGER NOT NULL,
			last_seen_ms INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY,
			layer TEXT NOT NULL,
			address TEXT NOT NULL,
			label TEXT NOT NULL,
			first_seen_ms INTEGER NOT NULL,
			UNIQUE (layer, address)
		);`,
		`CREATE TABLE IF NOT EXISTS event_samples (
			ts_ms INTEGER NOT NULL,
			target_id INTEGER NOT NULL,
			reached INTEGER NOT NULL,
			ok INTEGER NOT NULL,
			rtt_us INTEGER,
			err INTEGER,
			flags INTEGER NOT NULL DEFAULT 0,
			dns_us INTEGER,
			tcp_us INTEGER,
			tls_us INTEGER,
			ttfb_us INTEGER,
			status INTEGER,
			err_text TEXT,
			PRIMARY KEY (ts_ms, target_id)
		) WITHOUT ROWID;`,
		`CREATE TABLE IF NOT EXISTS rollups_1m (
			bucket_ms INTEGER NOT NULL,
			target_id INTEGER NOT NULL,
			sent INTEGER NOT NULL,
			reached INTEGER NOT NULL,
			ok INTEGER NOT NULL,
			flagged INTEGER NOT NULL,
			min_us INTEGER,
			p50_us INTEGER,
			p95_us INTEGER,
			max_us INTEGER,
			jitter_us INTEGER,
			PRIMARY KEY (bucket_ms, target_id)
		) WITHOUT ROWID;`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY,
			kind TEXT NOT NULL,
			classification TEXT NOT NULL,
			network_id INTEGER,
			start_ms INTEGER NOT NULL,
			start_uncert_ms INTEGER NOT NULL,
			end_ms INTEGER,
			end_uncert_ms INTEGER,
			duration_ms INTEGER,
			layers_down INTEGER NOT NULL DEFAULT 0,
			flags INTEGER NOT NULL DEFAULT 0,
			gateway_ok_pct REAL,
			isp_hop_ok_pct REAL,
			context TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS events_start ON events (start_ms);`,
		`CREATE TABLE IF NOT EXISTS system_events (
			id INTEGER PRIMARY KEY,
			ts_ms INTEGER NOT NULL,
			kind TEXT NOT NULL,
			detail TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS system_events_ts ON system_events (ts_ms);`,
		`CREATE TABLE IF NOT EXISTS coverage (
			id INTEGER PRIMARY KEY,
			network_id INTEGER,
			start_ms INTEGER NOT NULL,
			heartbeat_ms INTEGER NOT NULL,
			end_ms INTEGER,
			end_reason TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS profile_log (
				id INTEGER PRIMARY KEY,
				start_ms INTEGER NOT NULL,
				end_ms INTEGER,
				profile TEXT NOT NULL,
				profile_name TEXT NOT NULL,
				settings_hash TEXT NOT NULL,
				settings_json TEXT NOT NULL
			);`,
		`CREATE INDEX IF NOT EXISTS profile_log_start ON profile_log (start_ms);`,
		`INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}

	return migrateToV2(db)
}

// migrateToV2 brings a schema 1 database up to schema 2, which adds profile
// history: events.profile_id, and the profile_log table created above. Events
// written before it keep a NULL profile_id, which reads as Standard.
func migrateToV2(db *sql.DB) error {
	var hasProfileID int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'profile_id';`).Scan(&hasProfileID); err != nil {
		return err
	}
	if hasProfileID == 0 {
		if _, err := db.Exec(`ALTER TABLE events ADD COLUMN profile_id INTEGER REFERENCES profile_log (id);`); err != nil {
			return err
		}
	}

	_, err := db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value;`, SchemaVersion)
	return err
}

func PartitionTableName(t time.Time) string {
	return fmt.Sprintf("samples_%s", t.UTC().Format("20060102"))
}

func EnsurePartitionTable(db *sql.DB, tableName string) error {
	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		ts_ms INTEGER NOT NULL,
		target_id INTEGER NOT NULL,
		reached INTEGER NOT NULL,
		ok INTEGER NOT NULL,
		rtt_us INTEGER,
		err INTEGER,
		flags INTEGER NOT NULL DEFAULT 0,
		dns_us INTEGER,
		tcp_us INTEGER,
		tls_us INTEGER,
		ttfb_us INTEGER,
		status INTEGER,
		err_text TEXT
	);
	CREATE INDEX IF NOT EXISTS %s_ts ON %s (ts_ms);`, tableName, tableName, tableName)

	_, err := db.Exec(query)
	return err
}

func EnsurePartitionTableTx(tx *sql.Tx, tableName string) error {
	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		ts_ms INTEGER NOT NULL,
		target_id INTEGER NOT NULL,
		reached INTEGER NOT NULL,
		ok INTEGER NOT NULL,
		rtt_us INTEGER,
		err INTEGER,
		flags INTEGER NOT NULL DEFAULT 0,
		dns_us INTEGER,
		tcp_us INTEGER,
		tls_us INTEGER,
		ttfb_us INTEGER,
		status INTEGER,
		err_text TEXT
	);
	CREATE INDEX IF NOT EXISTS %s_ts ON %s (ts_ms);`, tableName, tableName, tableName)

	_, err := tx.Exec(query)
	return err
}
