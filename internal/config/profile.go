package config

import (
	"reflect"
	"regexp"
)

// Profile modes. Rotating probes one host of each slow layer per period;
// parallel probes every host of every layer each period, staggered across the
// tick.
const (
	ModeRotating = "rotating"
	ModeParallel = "parallel"
)

// Built-in profile ids. They are reserved: a custom profile can't use them.
const (
	ProfileStandard   = "standard"
	ProfileAggressive = "aggressive"
	ProfileLax        = "lax"

	// LegacyProfileID is the custom profile that settings edited in older
	// versions are migrated into.
	LegacyProfileID   = "previous-settings"
	LegacyProfileName = "Previous settings"
)

// Profile is one complete polling plan: how often each layer is probed, how
// long a probe may take and which hosts are probed.
//
// Built-in profiles are defined in code and never written to config.json.
// Custom profiles live in Config.Profiles.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Mode        string `json:"mode"`

	Intervals  IntervalsConfig `json:"intervals"`
	TimeoutsMS TimeoutsConfig  `json:"timeouts_ms"`
	Targets    TargetsConfig   `json:"targets"`

	// BuiltIn is set for profiles defined in code.
	BuiltIn bool `json:"-"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// IsReservedProfileID reports whether id belongs to a built-in profile.
func IsReservedProfileID(id string) bool {
	switch id {
	case ProfileStandard, ProfileAggressive, ProfileLax:
		return true
	}
	return false
}

// Clone returns a copy that shares no slices with p.
func (p Profile) Clone() Profile {
	t := p.Targets
	t.WANICMP = append([]string(nil), t.WANICMP...)
	t.WANTCP = append([]string(nil), t.WANTCP...)
	t.DNS = append([]string(nil), t.DNS...)
	t.HTTP = append([]HTTPTargetConfig(nil), t.HTTP...)
	p.Targets = t
	return p
}

func defaultTargets() TargetsConfig {
	return TargetsConfig{
		WANICMP: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		WANTCP:  []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"},
		DNS:     []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},

		DNSIncludeSystem: true,
		DNSQueryName:     "www.google.com",
		HTTP: []HTTPTargetConfig{
			{URL: "http://connectivitycheck.gstatic.com/generate_204", Status: 204},
			{URL: "http://www.msftconnecttest.com/connecttest.txt", Status: 200, BodyPrefix: "Microsoft Connect Test"},
			{URL: "https://www.google.com/generate_204", Status: 204},
		},
	}
}

// Standard is the profile every install starts on. Its values are the
// polling settings older versions hardcoded.
func Standard() Profile {
	return Profile{
		ID:          ProfileStandard,
		Name:        "Standard",
		Description: "Balanced default. The gateway and first ping host every second, other layers rotate through their hosts.",
		Mode:        ModeRotating,
		Intervals: IntervalsConfig{
			NormalMS:         1000,
			FastMS:           500,
			FastExitHealthyS: 10,
			FastMaxOutageS:   120,

			ISPHopMS:           2000,
			WANICMPSecondaryMS: 5000,
			WANTCPMS:           5000,
			DNSMS:              5000,
			HTTPMS:             15000,
		},
		TimeoutsMS: TimeoutsConfig{ICMP: 1000, TCP: 1200, DNS: 1200, HTTP: 2000},
		Targets:    defaultTargets(),
		BuiltIn:    true,
	}
}

// Aggressive probes every host of every layer each period, staggered across
// the tick, for the fastest detection and the most traffic.
func Aggressive() Profile {
	p := Standard()
	p.ID = ProfileAggressive
	p.Name = "Aggressive"
	p.Description = "Probes every host in every layer each period. Detects shorter outages and sends more traffic."
	p.Mode = ModeParallel
	p.Intervals.NormalMS = 500
	p.Intervals.FastMS = 500
	p.Intervals.ISPHopMS = 500
	p.Intervals.WANICMPSecondaryMS = 500
	p.Intervals.WANTCPMS = 2000
	p.Intervals.DNSMS = 2000
	p.Intervals.HTTPMS = 5000
	p.TimeoutsMS = TimeoutsConfig{ICMP: 800, TCP: 1000, DNS: 1000, HTTP: 2000}
	return p
}

// Lax keeps traffic low for metered or fragile links, at the cost of missing
// short outages.
func Lax() Profile {
	p := Standard()
	p.ID = ProfileLax
	p.Name = "Lax"
	p.Description = "Light touch. Rotates through hosts slowly and sends little traffic."
	p.Intervals.NormalMS = 5000
	p.Intervals.FastMS = 1000
	p.Intervals.ISPHopMS = 10000
	p.Intervals.WANICMPSecondaryMS = 30000
	p.Intervals.WANTCPMS = 30000
	p.Intervals.DNSMS = 30000
	p.Intervals.HTTPMS = 60000
	p.TimeoutsMS = TimeoutsConfig{ICMP: 2000, TCP: 2500, DNS: 2500, HTTP: 4000}
	return p
}

// BuiltInProfiles returns the built-in profiles in display order.
func BuiltInProfiles() []Profile {
	return []Profile{Standard(), Aggressive(), Lax()}
}

// sameSettings reports whether two profiles poll identically, ignoring id,
// name and description.
func sameSettings(a, b Profile) bool {
	return a.Mode == b.Mode &&
		a.Intervals == b.Intervals &&
		a.TimeoutsMS == b.TimeoutsMS &&
		reflect.DeepEqual(a.Targets, b.Targets)
}

// Normalize applies the technical minimums, which clamp rather than warn:
// unset or too-small values fall back to Standard's, and the slow-layer
// periods are raised to the normal interval. Host lists are left alone; an
// empty list means that layer is off.
func (p *Profile) Normalize() {
	d := Standard()
	if p.Mode == "" {
		p.Mode = ModeRotating
	}
	if p.Intervals.NormalMS < 200 {
		p.Intervals.NormalMS = d.Intervals.NormalMS
	}
	if p.Intervals.FastMS < 100 {
		p.Intervals.FastMS = d.Intervals.FastMS
	}
	if p.Intervals.FastExitHealthyS < 1 {
		p.Intervals.FastExitHealthyS = d.Intervals.FastExitHealthyS
	}
	if p.Intervals.FastMaxOutageS < 10 {
		p.Intervals.FastMaxOutageS = d.Intervals.FastMaxOutageS
	}
	for _, f := range []struct {
		v   *int
		def int
	}{
		{&p.Intervals.ISPHopMS, d.Intervals.ISPHopMS},
		{&p.Intervals.WANICMPSecondaryMS, d.Intervals.WANICMPSecondaryMS},
		{&p.Intervals.WANTCPMS, d.Intervals.WANTCPMS},
		{&p.Intervals.DNSMS, d.Intervals.DNSMS},
		{&p.Intervals.HTTPMS, d.Intervals.HTTPMS},
	} {
		if *f.v <= 0 {
			*f.v = f.def
		}
		if *f.v < p.Intervals.NormalMS {
			*f.v = p.Intervals.NormalMS
		}
	}
	if p.TimeoutsMS.ICMP < 200 {
		p.TimeoutsMS.ICMP = d.TimeoutsMS.ICMP
	}
	if p.TimeoutsMS.TCP < 200 {
		p.TimeoutsMS.TCP = d.TimeoutsMS.TCP
	}
	if p.TimeoutsMS.DNS < 200 {
		p.TimeoutsMS.DNS = d.TimeoutsMS.DNS
	}
	if p.TimeoutsMS.HTTP < 500 {
		p.TimeoutsMS.HTTP = d.TimeoutsMS.HTTP
	}
	if p.Targets.DNSQueryName == "" {
		p.Targets.DNSQueryName = d.Targets.DNSQueryName
	}
}
