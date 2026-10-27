package config

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type HTTPTargetConfig struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	BodyPrefix string `json:"body_prefix,omitempty"`
}

type HTTPConfig struct {
	// Enabled turns the dashboard web server on or off. Probing and
	// recording continue either way. Configs written before this field
	// existed keep the dashboard on.
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
}

// IntervalsConfig controls how often probes run.
//
// In normal mode the gateway and the first WAN ping host run every NormalMS.
// The other layers run less often, one rotating target at a time, on the
// periods below. While something looks wrong, fast mode probes every target
// every FastMS instead, so a failure is confirmed quickly.
type IntervalsConfig struct {
	NormalMS         int `json:"normal_ms"`
	FastMS           int `json:"fast_ms"`
	FastExitHealthyS int `json:"fast_exit_healthy_s"`
	FastMaxOutageS   int `json:"fast_max_outage_s"`

	// Normal-mode periods in milliseconds. A value below NormalMS is raised
	// to NormalMS; set them all to NormalMS to probe every layer every tick.
	ISPHopMS           int `json:"isp_hop_ms"`
	WANICMPSecondaryMS int `json:"wan_icmp_secondary_ms"`
	WANTCPMS           int `json:"wan_tcp_ms"`
	DNSMS              int `json:"dns_ms"`
	HTTPMS             int `json:"http_ms"`
}

type TimeoutsConfig struct {
	ICMP int `json:"icmp"`
	TCP  int `json:"tcp"`
	DNS  int `json:"dns"`
	HTTP int `json:"http"`
}

type TargetsConfig struct {
	WANICMP          []string           `json:"wan_icmp"`
	WANTCP           []string           `json:"wan_tcp"`
	DNS              []string           `json:"dns"`
	DNSIncludeSystem bool               `json:"dns_include_system"`
	DNSQueryName     string             `json:"dns_query_name"`
	HTTP             []HTTPTargetConfig `json:"http"`
}

type LatencyConfig struct {
	BaselineWindowS int     `json:"baseline_window_s"`
	LongWindowS     int     `json:"long_window_s"`
	WarmupSamples   int     `json:"warmup_samples"`
	MADK            float64 `json:"mad_k"`
	FloorMS         float64 `json:"floor_ms"`
	FloorPct        float64 `json:"floor_pct"`
	SpikeMS         float64 `json:"spike_ms"`
	SpikeX          float64 `json:"spike_x"`
	SustainOf       int     `json:"sustain_of"`
	SustainHits     int     `json:"sustain_hits"`
}

type RetentionConfig struct {
	RawPartitions   int `json:"raw_partitions"`
	EventWindowDays int `json:"event_window_days"`
	RollupDays      int `json:"rollup_days"`
	EventDays       int `json:"event_days"`
	MaxDBMB         int `json:"max_db_mb"`
	MinFreeDiskMB   int `json:"min_free_disk_mb"`
}

type UpdateConfig struct {
	CheckOnStartup bool   `json:"check_on_startup"`
	AutoCheckHours int    `json:"auto_check_hours"`
	Repo           string `json:"repo"`
}

type Config struct {
	HTTP             HTTPConfig      `json:"http"`
	Latency          LatencyConfig   `json:"latency"`
	Retention        RetentionConfig `json:"retention"`
	PostResumeGraceS int             `json:"post_resume_grace_s"`
	Update           UpdateConfig    `json:"update"`

	// ActiveProfile is the id of the profile the monitor runs. Profiles holds
	// the custom ones; the built-ins live in code.
	ActiveProfile string    `json:"active_profile"`
	Profiles      []Profile `json:"profiles"`

	// LoadWarnings lists things LoadConfig fixed or dropped, such as a custom
	// profile that broke the rules. It is never written to disk.
	LoadWarnings []string `json:"-"`
}

func DefaultConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			Enabled: true,
			Addr:    "127.0.0.1",
			Port:    9095,
		},
		Latency: LatencyConfig{
			BaselineWindowS: 300,
			LongWindowS:     1800,
			WarmupSamples:   60,
			MADK:            3.0,
			FloorMS:         20.0,
			FloorPct:        50.0,
			SpikeMS:         300.0,
			SpikeX:          5.0,
			SustainOf:       5,
			SustainHits:     3,
		},
		Retention: RetentionConfig{
			RawPartitions:   2,
			EventWindowDays: 30,
			RollupDays:      30,
			EventDays:       90,
			MaxDBMB:         500,
			MinFreeDiskMB:   1024,
		},
		PostResumeGraceS: 20,
		ActiveProfile:    ProfileStandard,
		Update: UpdateConfig{
			CheckOnStartup: true,
			AutoCheckHours: 24,
			Repo:           "aaronburt/netscan",
		},
	}
}

func isLoopback(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) ValidateAndApplyMinimums() {
	d := DefaultConfig()
	if !isLoopback(c.HTTP.Addr) {
		c.HTTP.Addr = d.HTTP.Addr
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		c.HTTP.Port = d.HTTP.Port
	}
	if c.ActiveProfile == "" {
		c.ActiveProfile = d.ActiveProfile
	}
	if c.Retention.RawPartitions < 1 {
		c.Retention.RawPartitions = 1
	}
	if c.Retention.EventWindowDays < 7 {
		c.Retention.EventWindowDays = 7
	}
	if c.Retention.RollupDays < 7 {
		c.Retention.RollupDays = 7
	}
	if c.Retention.EventDays < 30 {
		c.Retention.EventDays = 30
	}
	if c.Retention.MaxDBMB < 100 {
		c.Retention.MaxDBMB = d.Retention.MaxDBMB
	}
	if c.Retention.MinFreeDiskMB < 256 {
		c.Retention.MinFreeDiskMB = d.Retention.MinFreeDiskMB
	}
	if c.Latency.BaselineWindowS < 60 {
		c.Latency.BaselineWindowS = d.Latency.BaselineWindowS
	}
	if c.Latency.LongWindowS < 300 {
		c.Latency.LongWindowS = d.Latency.LongWindowS
	}
	if c.Latency.WarmupSamples < 10 {
		c.Latency.WarmupSamples = d.Latency.WarmupSamples
	}
	if c.Latency.MADK <= 0 {
		c.Latency.MADK = d.Latency.MADK
	}
	if c.Latency.FloorMS <= 0 {
		c.Latency.FloorMS = d.Latency.FloorMS
	}
	if c.Latency.FloorPct <= 0 {
		c.Latency.FloorPct = d.Latency.FloorPct
	}
	if c.Latency.SpikeMS <= 0 {
		c.Latency.SpikeMS = d.Latency.SpikeMS
	}
	if c.Latency.SpikeX <= 0 {
		c.Latency.SpikeX = d.Latency.SpikeX
	}
	if c.Latency.SustainOf < 1 {
		c.Latency.SustainOf = d.Latency.SustainOf
	}
	if c.Latency.SustainHits < 1 {
		c.Latency.SustainHits = d.Latency.SustainHits
	}
	if c.PostResumeGraceS < 5 {
		c.PostResumeGraceS = d.PostResumeGraceS
	}
	if c.Update.Repo == "" {
		c.Update.Repo = d.Update.Repo
	}
	if c.Update.AutoCheckHours < 0 {
		c.Update.AutoCheckHours = d.Update.AutoCheckHours
	}
}

func DataDir() string {
	return dataDir(runtime.GOOS, os.Getenv, os.UserHomeDir)
}

// dataDir resolves the data directory. NETSCAN_DATA_DIR always wins. On Linux
// the order continues with STATE_DIRECTORY (set by systemd's StateDirectory=),
// then XDG_DATA_HOME, then ~/.local/share.
func dataDir(goos string, getenv func(string) string, homeDir func() (string, error)) string {
	if dir := getenv("NETSCAN_DATA_DIR"); dir != "" {
		return dir
	}
	if goos != "windows" {
		if dir := getenv("STATE_DIRECTORY"); dir != "" {
			// systemd may list several directories separated by a colon.
			return strings.SplitN(dir, ":", 2)[0]
		}
		if dir := getenv("XDG_DATA_HOME"); dir != "" {
			return filepath.Join(dir, "netscan")
		}
		home, err := homeDir()
		if err != nil {
			return ".netscan"
		}
		return filepath.Join(home, ".local", "share", "netscan")
	}
	appData := getenv("LOCALAPPDATA")
	if appData == "" {
		home, err := homeDir()
		if err != nil {
			return ".netscan"
		}
		return filepath.Join(home, "AppData", "Local", "NetScan")
	}
	return filepath.Join(appData, "NetScan")
}

func EnsureDataDir() (string, error) {
	dir := DataDir()
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return "", err
	}
	logsDir := filepath.Join(dir, "logs")
	err = os.MkdirAll(logsDir, 0755)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func ConfigPath() string {
	return filepath.Join(DataDir(), "config.json")
}

func DBPath() string {
	return filepath.Join(DataDir(), "netscan.db")
}

func PortPath() string {
	return filepath.Join(DataDir(), "port")
}

func AppLogPath() string {
	return filepath.Join(DataDir(), "logs", "app.log")
}

// SetWebUIEnabled persists the dashboard on/off choice, leaving the rest of
// the config at what is on disk (or defaults if the file is missing).
func SetWebUIEnabled(path string, enabled bool) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	cfg.HTTP.Enabled = enabled
	return SaveConfig(path, cfg)
}
