package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// saveMu serialises config writes so two saves can't interleave their
// temp-file-and-rename steps.
var saveMu sync.Mutex

// FindProfile looks a profile up by id, built-ins first.
func (c Config) FindProfile(id string) (Profile, bool) {
	for _, p := range c.AllProfiles() {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

// AllProfiles returns the built-in profiles followed by the custom ones.
func (c Config) AllProfiles() []Profile {
	all := BuiltInProfiles()
	for _, p := range c.Profiles {
		all = append(all, p.Clone())
	}
	return all
}

// Active returns the profile the monitor should run. An unknown id falls back
// to Standard.
func (c Config) Active() Profile {
	if p, ok := c.FindProfile(c.ActiveProfile); ok {
		return p
	}
	return Standard()
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = ConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		cfg := DefaultConfig()
		if errors.Is(err, os.ErrNotExist) {
			return cfg, SaveConfig(path, cfg)
		}
		return cfg, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		cfg.ValidateAndApplyMinimums()
		cfg.resolveProfiles(nil)
		return cfg, err
	}

	cfg.ValidateAndApplyMinimums()
	cfg.resolveProfiles(legacyProfile(data))
	return cfg, nil
}

// legacyProfile reads the top-level intervals, timeouts_ms and targets keys
// that versions before profiles wrote. It returns nil when the file already
// uses profiles or when those settings equal Standard, in which case Standard
// stays active. Otherwise the settings come back as a custom profile.
func legacyProfile(data []byte) *Profile {
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) != nil {
		return nil
	}
	if _, ok := keys["active_profile"]; ok {
		return nil
	}
	_, hasIntervals := keys["intervals"]
	_, hasTimeouts := keys["timeouts_ms"]
	_, hasTargets := keys["targets"]
	if !hasIntervals && !hasTimeouts && !hasTargets {
		return nil
	}

	p := Standard()
	// encoding/json decodes into the existing elements of a slice, so a
	// shorter or different "http" list would inherit fields (like
	// body_prefix) from the default entry at the same position.
	p.Targets.HTTP = nil
	v := struct {
		Intervals  *IntervalsConfig `json:"intervals"`
		TimeoutsMS *TimeoutsConfig  `json:"timeouts_ms"`
		Targets    *TargetsConfig   `json:"targets"`
	}{&p.Intervals, &p.TimeoutsMS, &p.Targets}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}

	// Older versions put the defaults back for an empty host list.
	d := defaultTargets()
	if len(p.Targets.WANICMP) == 0 {
		p.Targets.WANICMP = d.WANICMP
	}
	if len(p.Targets.WANTCP) == 0 {
		p.Targets.WANTCP = d.WANTCP
	}
	if len(p.Targets.DNS) == 0 {
		p.Targets.DNS = d.DNS
	}
	if len(p.Targets.HTTP) == 0 {
		p.Targets.HTTP = d.HTTP
	}
	p.Normalize()

	if sameSettings(p, Standard()) {
		return nil
	}
	p.ID = LegacyProfileID
	p.Name = LegacyProfileName
	p.Description = "Settings carried over from an earlier version."
	p.BuiltIn = false
	return &p
}

// resolveProfiles cleans up the custom profiles read from disk and settles
// which one is active. Profiles that break the rules are dropped with a
// warning rather than failing the whole load. A migrated legacy profile is
// kept even if it breaks the shape rules, since it is what the user was
// already running.
func (c *Config) resolveProfiles(legacy *Profile) {
	var kept []Profile
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		p.BuiltIn = false
		p.Normalize()
		switch {
		case IsReservedProfileID(p.ID):
			c.warnf("profile %q uses a reserved id and was ignored", p.ID)
			continue
		case seen[p.ID]:
			c.warnf("profile id %q is used twice; the second was ignored", p.ID)
			continue
		}
		if errs := p.Validate().Errors; len(errs) > 0 {
			c.warnf("profile %q was ignored: %s %s", p.ID, errs[0].Field, errs[0].Message)
			continue
		}
		seen[p.ID] = true
		kept = append(kept, p)
	}

	if legacy != nil {
		if errs := legacy.Validate().Errors; len(errs) > 0 {
			c.warnf("%s breaks the profile rules (%s %s) and is kept as it was", LegacyProfileName, errs[0].Field, errs[0].Message)
		}
		kept = append(kept, *legacy)
		c.ActiveProfile = legacy.ID
	}
	c.Profiles = kept

	if len(kept) > LimitCustomProfiles {
		c.warnf("%d custom profiles; more than %d is not recommended", len(kept), LimitCustomProfiles)
	}
	if _, ok := c.FindProfile(c.ActiveProfile); !ok {
		c.warnf("active profile %q not found; using Standard", c.ActiveProfile)
		c.ActiveProfile = ProfileStandard
	}
}

func (c *Config) warnf(format string, a ...any) {
	c.LoadWarnings = append(c.LoadWarnings, fmt.Sprintf(format, a...))
}

// SaveConfig writes the config atomically: a temp file in the same directory
// is renamed over the target, so a crash never leaves half a file. A file in
// the pre-profile shape is copied to path+".bak" first.
func SaveConfig(path string, cfg Config) error {
	if path == "" {
		path = ConfigPath()
	}
	saveMu.Lock()
	defer saveMu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = []Profile{}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if old, err := os.ReadFile(path); err == nil && !bytes.Contains(old, []byte(`"active_profile"`)) {
		if err := os.WriteFile(path+".bak", old, 0644); err != nil {
			return fmt.Errorf("back up config: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmpName, 0644)
	}
	if werr == nil {
		werr = os.Rename(tmpName, path)
	}
	if werr != nil {
		os.Remove(tmpName)
		return werr
	}
	return nil
}
