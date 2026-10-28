package store

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
)

// ProfileRecord is one stretch of monitoring under a single profile. Events
// point at the row that was open when they started, so the row keeps the
// settings it ran with even after the profile is edited or deleted.
type ProfileRecord struct {
	ID           int64  `json:"id"`
	StartMS      int64  `json:"start_ms"`
	EndMS        *int64 `json:"end_ms,omitempty"`
	Profile      string `json:"profile"`
	ProfileName  string `json:"profile_name"`
	SettingsHash string `json:"settings_hash"`
	SettingsJSON string `json:"-"`
}

// ProfileHistory writes profile_log: a row for each stretch of monitoring under
// one set of settings. The switcher and shutdown both use it, so it has its own
// lock.
type ProfileHistory struct {
	mu      sync.Mutex
	writer  *StoreWriter
	nextID  int64
	current *ProfileRecord
}

// NewProfileHistory returns the recorder for this run. Rows still open came
// from a run that didn't shut down cleanly, so they are closed at `at`, where
// this run starts. The time in between counts towards the profile that was
// running, because nothing was recorded when it stopped.
func NewProfileHistory(db *sql.DB, writer *StoreWriter, at time.Time) (*ProfileHistory, error) {
	if _, err := db.Exec(`UPDATE profile_log SET end_ms = ? WHERE end_ms IS NULL;`, at.UnixMilli()); err != nil {
		return nil, err
	}

	var maxID int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM profile_log;`).Scan(&maxID); err != nil {
		return nil, err
	}
	return &ProfileHistory{writer: writer, nextID: maxID + 1}, nil
}

// Switch records that p is in force from `at`, closing the row before it, and
// returns the id of p's row. Settings identical to the current row's change
// nothing and return that row's id.
func (h *ProfileHistory) Switch(p config.Profile, at time.Time) int64 {
	hash, snapshot := p.Fingerprint()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.current != nil && h.current.SettingsJSON == snapshot {
		return h.current.ID
	}
	if h.current != nil {
		h.endCurrent(at)
	}

	next := ProfileRecord{
		ID:           h.nextID,
		StartMS:      at.UnixMilli(),
		Profile:      p.ID,
		ProfileName:  p.Name,
		SettingsHash: hash,
		SettingsJSON: snapshot,
	}
	h.nextID++
	h.writer.QueueProfile(next)
	h.current = &next
	return next.ID
}

// Close ends the open row at `at`. It is called on a clean shutdown.
func (h *ProfileHistory) Close(at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.current != nil {
		h.endCurrent(at)
		h.current = nil
	}
}

// endCurrent writes the end time of the open row. Callers hold h.mu.
func (h *ProfileHistory) endCurrent(at time.Time) {
	end := at.UnixMilli()
	h.current.EndMS = &end
	h.writer.QueueProfile(*h.current)
}

// QueryProfiles returns the profile rows that overlap [fromMS, toMS], oldest
// first. A row that is still open counts as open until toMS.
func (r *StoreReader) QueryProfiles(fromMS, toMS int64) ([]ProfileRecord, error) {
	rows, err := r.db.Query(`SELECT id, start_ms, end_ms, profile, profile_name, settings_hash, settings_json
		FROM profile_log
		WHERE start_ms <= ? AND (end_ms IS NULL OR end_ms >= ?)
		ORDER BY start_ms ASC, id ASC;`, toMS, fromMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []ProfileRecord{}
	for rows.Next() {
		var p ProfileRecord
		var endMS sql.NullInt64
		if err := rows.Scan(&p.ID, &p.StartMS, &endMS, &p.Profile, &p.ProfileName, &p.SettingsHash, &p.SettingsJSON); err != nil {
			return nil, err
		}
		if endMS.Valid {
			p.EndMS = &endMS.Int64
		}
		records = append(records, p)
	}
	return records, rows.Err()
}

// ProfileUse is how much of a period one set of profile settings covered, and
// what those settings cost to run.
type ProfileUse struct {
	ID           string              `json:"profile"`
	Name         string              `json:"name"`
	SettingsHash string              `json:"settings_hash"`
	DurationMS   int64               `json:"duration_ms"`
	SharePct     float64             `json:"share_pct"`
	Estimate     config.LoadEstimate `json:"estimate"`
}

// SummarizeProfiles works out how much of [fromMS, toMS] each profile covered.
// Rows are grouped by settings, so an edited profile shows as its own entry
// with its own load figures. Shares are of the time that had a profile
// recorded, so they add up to 100 for any period with history.
func SummarizeProfiles(rows []ProfileRecord, fromMS, toMS int64) []ProfileUse {
	usage := []ProfileUse{}
	index := map[string]int{}
	var total int64

	for _, r := range rows {
		end := toMS
		if r.EndMS != nil && *r.EndMS < end {
			end = *r.EndMS
		}
		dur := end - max(r.StartMS, fromMS)
		if dur <= 0 {
			continue
		}
		total += dur

		i, ok := index[r.SettingsHash]
		if !ok {
			i = len(usage)
			index[r.SettingsHash] = i
			usage = append(usage, ProfileUse{
				ID:           r.Profile,
				SettingsHash: r.SettingsHash,
				Estimate:     estimateSnapshot(r.SettingsJSON),
			})
		}
		usage[i].Name = r.ProfileName
		usage[i].DurationMS += dur
	}

	if total > 0 {
		for i := range usage {
			usage[i].SharePct = float64(usage[i].DurationMS) / float64(total) * 100
		}
	}
	return usage
}

// nullableID stores 0 as NULL. That is how an event with no profile recorded,
// such as one from before profile history, reads back.
func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// estimateSnapshot works out the load of a stored settings snapshot. One that
// doesn't parse gives a zero estimate rather than failing the whole report.
func estimateSnapshot(snapshot string) config.LoadEstimate {
	var p config.Profile
	if err := json.Unmarshal([]byte(snapshot), &p); err != nil {
		return config.LoadEstimate{}
	}
	return p.Estimate()
}
