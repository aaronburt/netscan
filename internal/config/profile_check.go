package config

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
)

// Safety limits. Going past one produces a warning that the user can
// override, never a hard failure. Private addresses are exempt.
const (
	LimitMinICMPIntervalMS = 250
	LimitMinTCPIntervalMS  = 1000
	LimitMinDNSIntervalMS  = 1000
	LimitMinHTTPIntervalMS = 5000
	LimitMinFastMS         = 250

	LimitHostProbesPerSec     = 5.0
	LimitHostFastProbesPerSec = 10.0
	LimitRemoteProbesPerSec   = 20.0

	LimitHostsPerLayer  = 8
	LimitHostsPerProf   = 24
	LimitCustomProfiles = 16
)

// Layer names used in load estimates and field paths.
const (
	layerGateway = "gateway"
	layerISPHop  = "isp_hop"
	layerICMP    = "icmp"
	layerTCP     = "tcp"
	layerDNS     = "dns"
	layerHTTP    = "http"
)

// Issue is one problem with one field of a profile.
type Issue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Check is the result of validating a profile. Errors must be fixed; Warnings
// are limit breaches that can be overridden.
type Check struct {
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

// HostLoad is how often one host is probed.
type HostLoad struct {
	Layer            string  `json:"layer"`
	Address          string  `json:"address"`
	IntervalMS       int     `json:"interval_ms"`
	ProbesPerSec     float64 `json:"probes_per_s"`
	FastProbesPerSec float64 `json:"fast_probes_per_s"`
	Private          bool    `json:"private"`
}

// LoadEstimate is what a profile costs, worked out from its settings alone.
// The gateway and ISP hop are included because every network has them; system
// DNS resolvers are not, because they are only known at runtime.
type LoadEstimate struct {
	Hosts              []HostLoad `json:"hosts"`
	ProbesPerSec       float64    `json:"probes_per_s"`
	RemoteProbesPerSec float64    `json:"remote_probes_per_s"`
	FastProbesPerSec   float64    `json:"fast_probes_per_s"`
	RowsPerDay         int64      `json:"rows_per_day"`

	// MinDetectableOutageMS is a rough figure: the longest an outage can last
	// without being guaranteed a probe, plus the time fast mode needs to
	// confirm it.
	MinDetectableOutageMS int `json:"min_detectable_outage_ms"`
}

// hostAddr extracts the host part of a probe address.
func hostAddr(layer, addr string) string {
	if layer == layerHTTP {
		if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		return addr
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

// isPrivateHost reports whether the host is on the local network or the
// machine itself, where probing costs the internet nothing.
func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// Estimate works out the probe rates a profile produces.
func (p Profile) Estimate() LoadEstimate {
	iv := p.Intervals
	parallel := p.Mode == ModeParallel
	var est LoadEstimate

	add := func(layer, addr string, intervalMS int, private bool) {
		if intervalMS <= 0 {
			return
		}
		h := HostLoad{
			Layer:            layer,
			Address:          addr,
			IntervalMS:       intervalMS,
			ProbesPerSec:     1000 / float64(intervalMS),
			FastProbesPerSec: 1000 / float64(max(iv.FastMS, 1)),
			Private:          private,
		}
		est.Hosts = append(est.Hosts, h)
		est.ProbesPerSec += h.ProbesPerSec
		est.FastProbesPerSec += h.FastProbesPerSec
		if !private {
			est.RemoteProbesPerSec += h.ProbesPerSec
		}
	}
	// rotating layers visit one host per period, so each host waits n periods.
	perHost := func(periodMS, n int) int {
		if parallel {
			return periodMS
		}
		return periodMS * n
	}

	add(layerGateway, "gateway", iv.NormalMS, true)
	add(layerISPHop, "ISP hop", iv.ISPHopMS, false)
	for i, a := range p.Targets.WANICMP {
		interval := iv.NormalMS
		if i > 0 {
			interval = perHost(iv.WANICMPSecondaryMS, len(p.Targets.WANICMP)-1)
		}
		add(layerICMP, a, interval, isPrivateHost(hostAddr(layerICMP, a)))
	}
	for _, a := range p.Targets.WANTCP {
		add(layerTCP, a, perHost(iv.WANTCPMS, len(p.Targets.WANTCP)), isPrivateHost(hostAddr(layerTCP, a)))
	}
	for _, a := range p.Targets.DNS {
		add(layerDNS, a, perHost(iv.DNSMS, len(p.Targets.DNS)), isPrivateHost(hostAddr(layerDNS, a)))
	}
	for _, h := range p.Targets.HTTP {
		add(layerHTTP, h.URL, perHost(iv.HTTPMS, len(p.Targets.HTTP)), isPrivateHost(hostAddr(layerHTTP, h.URL)))
	}

	est.RowsPerDay = int64(math.Round(est.ProbesPerSec * 86400))

	timeout := 0
	if len(p.Targets.WANTCP) > 0 {
		timeout = max(timeout, p.TimeoutsMS.TCP)
	}
	if len(p.Targets.DNS) > 0 {
		timeout = max(timeout, p.TimeoutsMS.DNS)
	}
	if len(p.Targets.HTTP) > 0 {
		timeout = max(timeout, p.TimeoutsMS.HTTP)
	}
	est.MinDetectableOutageMS = iv.NormalMS + iv.FastMS + timeout
	return est
}

func hostCounts(t TargetsConfig) (icmp, tcp, dns, http int) {
	return len(t.WANICMP), len(t.WANTCP), len(t.DNS), len(t.HTTP)
}

// Validate checks a profile against the rules every profile must follow
// (errors) and the safety limits (warnings). It expects a normalized profile.
func (p Profile) Validate() Check {
	var c Check
	errf := func(field, format string, a ...any) {
		c.Errors = append(c.Errors, Issue{field, fmt.Sprintf(format, a...)})
	}
	warnf := func(field, format string, a ...any) {
		c.Warnings = append(c.Warnings, Issue{field, fmt.Sprintf(format, a...)})
	}

	if !idPattern.MatchString(p.ID) {
		errf("id", "must be 1-32 lowercase letters, digits or dashes")
	}
	if strings.TrimSpace(p.Name) == "" {
		errf("name", "is required")
	} else if len([]rune(p.Name)) > 40 {
		errf("name", "must be 40 characters or fewer")
	}
	if len([]rune(p.Description)) > 200 {
		errf("description", "must be 200 characters or fewer")
	}
	if p.Mode != ModeRotating && p.Mode != ModeParallel {
		errf("mode", "must be %q or %q", ModeRotating, ModeParallel)
	}

	seen := map[string]bool{}
	checkList := func(field, layer string, addrs []string) {
		for i, a := range addrs {
			f := fmt.Sprintf("targets.%s[%d]", field, i)
			if strings.TrimSpace(a) == "" {
				errf(f, "is empty")
				continue
			}
			if k := layer + "|" + a; seen[k] {
				errf(f, "%q is listed twice", a)
			} else {
				seen[k] = true
			}
		}
	}
	checkList("wan_icmp", layerICMP, p.Targets.WANICMP)
	checkList("wan_tcp", layerTCP, p.Targets.WANTCP)
	checkList("dns", layerDNS, p.Targets.DNS)
	for i, h := range p.Targets.HTTP {
		f := fmt.Sprintf("targets.http[%d]", i)
		u, err := url.Parse(h.URL)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "":
			errf(f+".url", "must be an http:// or https:// URL")
		case seen[layerHTTP+"|"+h.URL]:
			errf(f+".url", "%q is listed twice", h.URL)
		default:
			seen[layerHTTP+"|"+h.URL] = true
		}
		if h.Status != 0 && (h.Status < 100 || h.Status > 599) {
			errf(f+".status", "must be an HTTP status code")
		}
	}

	// The outage rule needs two of TCP, DNS and HTTP to fail together, so a
	// profile must keep at least two of them on, each with a second host to
	// confirm against.
	icmp, tcp, dns, http := hostCounts(p.Targets)
	enabled := 0
	for _, l := range []struct {
		field string
		n     int
	}{{"targets.wan_tcp", tcp}, {"targets.dns", dns}, {"targets.http", http}} {
		if l.n == 0 {
			continue
		}
		enabled++
		if l.n < 2 {
			errf(l.field, "needs at least 2 hosts when the layer is enabled")
		}
	}
	if enabled < 2 {
		errf("targets", "at least 2 of TCP, DNS and HTTP must be enabled (outages need two layers failing together)")
	}

	// Limits.
	for _, l := range []struct {
		field string
		n     int
	}{{"targets.wan_icmp", icmp}, {"targets.wan_tcp", tcp}, {"targets.dns", dns}, {"targets.http", http}} {
		if l.n > LimitHostsPerLayer {
			warnf(l.field, "%d hosts; more than %d per layer is a lot of traffic", l.n, LimitHostsPerLayer)
		}
	}
	if n := icmp + tcp + dns + http; n > LimitHostsPerProf {
		warnf("targets", "%d hosts; more than %d per profile is a lot of traffic", n, LimitHostsPerProf)
	}

	est := p.Estimate()
	minInterval := map[string]int{
		layerISPHop: LimitMinICMPIntervalMS, layerICMP: LimitMinICMPIntervalMS,
		layerTCP: LimitMinTCPIntervalMS, layerDNS: LimitMinDNSIntervalMS, layerHTTP: LimitMinHTTPIntervalMS,
	}
	fastPublic := false
	for _, h := range est.Hosts {
		if h.Private {
			continue
		}
		fastPublic = true
		if min, ok := minInterval[h.Layer]; ok && h.IntervalMS < min {
			warnf("hosts."+h.Address, "probed every %dms; the suggested minimum for %s is %dms", h.IntervalMS, h.Layer, min)
		}
		if h.ProbesPerSec > LimitHostProbesPerSec {
			warnf("hosts."+h.Address, "%.1f probes/s; more than %.0f/s hits one host hard", h.ProbesPerSec, LimitHostProbesPerSec)
		}
		if h.FastProbesPerSec > LimitHostFastProbesPerSec {
			warnf("hosts."+h.Address, "%.1f probes/s in fast mode; more than %.0f/s hits one host hard", h.FastProbesPerSec, LimitHostFastProbesPerSec)
		}
	}
	if fastPublic && p.Intervals.FastMS < LimitMinFastMS {
		warnf("intervals.fast_ms", "%dms; the suggested minimum is %dms", p.Intervals.FastMS, LimitMinFastMS)
	}
	if est.RemoteProbesPerSec > LimitRemoteProbesPerSec {
		warnf("intervals", "%.1f probes/s to remote hosts; more than %.0f/s is a lot of traffic", est.RemoteProbesPerSec, LimitRemoteProbesPerSec)
	}
	return c
}
