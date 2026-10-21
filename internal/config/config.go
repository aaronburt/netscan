package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
)

type HTTPTargetConfig struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	BodyPrefix string `json:"body_prefix,omitempty"`
}

type HTTPConfig struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

type IntervalsConfig struct {
	NormalMS         int `json:"normal_ms"`
	FastMS           int `json:"fast_ms"`
	FastExitHealthyS int `json:"fast_exit_healthy_s"`
	FastMaxOutageS   int `json:"fast_max_outage_s"`
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
	Intervals        IntervalsConfig `json:"intervals"`
	TimeoutsMS       TimeoutsConfig  `json:"timeouts_ms"`
	Targets          TargetsConfig   `json:"targets"`
	Latency          LatencyConfig   `json:"latency"`
	Retention        RetentionConfig `json:"retention"`
	PostResumeGraceS int             `json:"post_resume_grace_s"`
	Update           UpdateConfig    `json:"update"`
}

func DefaultConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			Addr: "127.0.0.1",
			Port: 9095,
		},
		Intervals: IntervalsConfig{
			NormalMS:         1000,
			FastMS:           500,
			FastExitHealthyS: 10,
			FastMaxOutageS:   120,
		},
		TimeoutsMS: TimeoutsConfig{
			ICMP: 1000,
			TCP:  1200,
			DNS:  1200,
			HTTP: 2000,
		},
		Targets: TargetsConfig{
			WANICMP: []string{
				"1.1.1.1",
				"8.8.8.8",
				"9.9.9.9",
			},
			WANTCP: []string{
				"1.1.1.1:443",
				"8.8.8.8:443",
				"9.9.9.9:443",
			},
			DNS: []string{
				"1.1.1.1:53",
				"8.8.8.8:53",
				"9.9.9.9:53",
			},
			DNSIncludeSystem: true,
			DNSQueryName:     "www.google.com",
			HTTP: []HTTPTargetConfig{
				{
					URL:    "http://connectivitycheck.gstatic.com/generate_204",
					Status: 204,
				},
				{
					URL:        "http://www.msftconnecttest.com/connecttest.txt",
					Status:     200,
					BodyPrefix: "Microsoft Connect Test",
				},
				{
					URL:    "https://www.google.com/generate_204",
					Status: 204,
				},
			},
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
	if c.Intervals.NormalMS < 200 {
		c.Intervals.NormalMS = d.Intervals.NormalMS
	}
	if c.Intervals.FastMS < 100 {
		c.Intervals.FastMS = d.Intervals.FastMS
	}
	if c.Intervals.FastExitHealthyS < 1 {
		c.Intervals.FastExitHealthyS = d.Intervals.FastExitHealthyS
	}
	if c.Intervals.FastMaxOutageS < 10 {
		c.Intervals.FastMaxOutageS = d.Intervals.FastMaxOutageS
	}
	if c.TimeoutsMS.ICMP < 200 {
		c.TimeoutsMS.ICMP = d.TimeoutsMS.ICMP
	}
	if c.TimeoutsMS.TCP < 200 {
		c.TimeoutsMS.TCP = d.TimeoutsMS.TCP
	}
	if c.TimeoutsMS.DNS < 200 {
		c.TimeoutsMS.DNS = d.TimeoutsMS.DNS
	}
	if c.TimeoutsMS.HTTP < 500 {
		c.TimeoutsMS.HTTP = d.TimeoutsMS.HTTP
	}
	if len(c.Targets.WANICMP) == 0 {
		c.Targets.WANICMP = d.Targets.WANICMP
	}
	if len(c.Targets.WANTCP) == 0 {
		c.Targets.WANTCP = d.Targets.WANTCP
	}
	if len(c.Targets.DNS) == 0 {
		c.Targets.DNS = d.Targets.DNS
	}
	if c.Targets.DNSQueryName == "" {
		c.Targets.DNSQueryName = d.Targets.DNSQueryName
	}
	if len(c.Targets.HTTP) == 0 {
		c.Targets.HTTP = d.Targets.HTTP
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
	if dir := os.Getenv("NETSCAN_DATA_DIR"); dir != "" {
		return dir
	}
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		home, err := os.UserHomeDir()
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

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = ConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := DefaultConfig()
			saveErr := SaveConfig(path, cfg)
			return cfg, saveErr
		}
		cfg := DefaultConfig()
		return cfg, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		cfg.ValidateAndApplyMinimums()
		return cfg, err
	}

	cfg.ValidateAndApplyMinimums()
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	if path == "" {
		path = ConfigPath()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
