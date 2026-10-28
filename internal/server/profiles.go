package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/switcher"
)

// maxProfileBody bounds a profile request. Even a profile at the host limit is
// a few kilobytes.
const maxProfileBody = 64 << 10

// errNoProfiles is returned by profile changes on a server that was not given
// a switcher with SetProfiles.
var errNoProfiles = errors.New("profiles are not set up")

// profileRequest is a profile as the dashboard sends it. Override accepts the
// safety-limit warnings that would otherwise refuse the profile.
type profileRequest struct {
	config.Profile
	Override bool `json:"override"`
}

// profileView is one profile as the profiles API reports it.
type profileView struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Mode        string                 `json:"mode"`
	BuiltIn     bool                   `json:"built_in"`
	Active      bool                   `json:"active"`
	Intervals   config.IntervalsConfig `json:"intervals"`
	TimeoutsMS  config.TimeoutsConfig  `json:"timeouts_ms"`
	Targets     config.TargetsConfig   `json:"targets"`
	Estimate    config.LoadEstimate    `json:"estimate"`
	Warnings    []config.Issue         `json:"warnings"`
}

// profileLimits are the safety limits profiles are checked against. Going past
// one is a warning the user can override; the built-in profiles stay inside.
type profileLimits struct {
	MinICMPIntervalMS  int     `json:"min_icmp_interval_ms"`
	MinTCPIntervalMS   int     `json:"min_tcp_interval_ms"`
	MinDNSIntervalMS   int     `json:"min_dns_interval_ms"`
	MinHTTPIntervalMS  int     `json:"min_http_interval_ms"`
	MinFastMS          int     `json:"min_fast_ms"`
	HostProbesPerS     float64 `json:"host_probes_per_s"`
	HostFastProbesPerS float64 `json:"host_fast_probes_per_s"`
	RemoteProbesPerS   float64 `json:"remote_probes_per_s"`
	HostsPerLayer      int     `json:"hosts_per_layer"`
	HostsPerProfile    int     `json:"hosts_per_profile"`
	CustomProfiles     int     `json:"custom_profiles"`
}

var profileLimitsView = profileLimits{
	MinICMPIntervalMS:  config.LimitMinICMPIntervalMS,
	MinTCPIntervalMS:   config.LimitMinTCPIntervalMS,
	MinDNSIntervalMS:   config.LimitMinDNSIntervalMS,
	MinHTTPIntervalMS:  config.LimitMinHTTPIntervalMS,
	MinFastMS:          config.LimitMinFastMS,
	HostProbesPerS:     config.LimitHostProbesPerSec,
	HostFastProbesPerS: config.LimitHostFastProbesPerSec,
	RemoteProbesPerS:   config.LimitRemoteProbesPerSec,
	HostsPerLayer:      config.LimitHostsPerLayer,
	HostsPerProfile:    config.LimitHostsPerProf,
	CustomProfiles:     config.LimitCustomProfiles,
}

// profilesResponse is the state of the profiles: which one runs, all of them
// and the limits.
type profilesResponse struct {
	ActiveProfile string        `json:"active_profile"`
	Profiles      []profileView `json:"profiles"`
	Limits        profileLimits `json:"limits"`
}

// reloadResponse is the profiles after a reload, with the warnings from
// reading config.json.
type reloadResponse struct {
	profilesResponse
	LoadWarnings []string `json:"load_warnings"`
}

// profileProblem explains why a profile change was refused.
type profileProblem struct {
	Error         string         `json:"error"`
	Errors        []config.Issue `json:"errors"`
	Warnings      []config.Issue `json:"warnings"`
	NeedsOverride bool           `json:"needs_override"`
}

// validateResponse is the result of a dry run. Nothing is saved.
type validateResponse struct {
	Valid    bool                `json:"valid"`
	Errors   []config.Issue      `json:"errors"`
	Warnings []config.Issue      `json:"warnings"`
	Estimate config.LoadEstimate `json:"estimate"`
}

// hostTestResult is one host as the test probe saw it.
type hostTestResult struct {
	Layer   string  `json:"layer"`
	Address string  `json:"address"`
	OK      bool    `json:"ok"`
	RTTMS   float64 `json:"rtt_ms"`
	Status  int     `json:"status,omitempty"`
	Error   string  `json:"error,omitempty"`
}

type testHostsResponse struct {
	Results []hostTestResult `json:"results"`
	Notes   []string         `json:"notes"`
}

// SetProfiles gives the profile routes the switcher that applies a profile and
// the config.json they save to ("" for the default location). Until it is
// called, the profile routes list profiles but refuse every change.
func (s *Server) SetProfiles(sw *switcher.Switcher, path string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.profiles = sw
	s.profilesPath = path
	s.custom = cloneProfiles(s.cfg.Profiles)
}

// ReloadProfiles re-reads config.json and switches to its active profile. The
// reload route and SIGHUP both use it. It returns the warnings from reading the
// file. If the file can't be read, nothing changes.
func (s *Server) ReloadProfiles() ([]string, error) {
	sw, path, err := s.profileState()
	if err != nil {
		return nil, err
	}
	s.profilesMu.Lock()
	defer s.profilesMu.Unlock()

	cfg, err := config.LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("config.json could not be read, so the running profile is unchanged: %w", err)
	}
	s.setCustom(cfg.Profiles)
	return cfg.LoadWarnings, applyIfChanged(sw, cfg.Active())
}

// handleProfiles lists the profiles, or adds a custom one.
func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.listProfiles())
	case http.MethodPost:
		s.createProfile(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProfile edits, deletes or activates the profile named in the path.
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/profiles/"), "/")
	switch {
	case id == "":
		http.NotFound(w, r)
	case action == "activate":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.activateProfile(w, r, id)
	case action != "":
		http.NotFound(w, r)
	case r.Method == http.MethodPut:
		s.updateProfile(w, r, id)
	case r.Method == http.MethodDelete:
		s.deleteProfile(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// createProfile adds a custom profile to config.json. Without an id, one is made
// from the name.
func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var req profileRequest
	if !readProfileRequest(w, r, &req) {
		return
	}
	_, path, ok := s.profileStateOr503(w)
	if !ok {
		return
	}
	s.profilesMu.Lock()
	defer s.profilesMu.Unlock()

	cfg, ok := loadForWrite(w, path)
	if !ok {
		return
	}
	p := req.Profile
	if p.ID == "" {
		p.ID = cfg.NewProfileID(p.Name)
	}
	p.BuiltIn = false
	p.Normalize()
	if !allowSave(w, cfg.CheckCandidate(p, ""), req.Override) {
		return
	}
	cfg.Profiles = append(cfg.Profiles, p)
	if !s.saveProfiles(w, path, cfg) {
		return
	}
	writeJSON(w, http.StatusCreated, s.listProfiles())
}

// updateProfile replaces the settings of a custom profile. When that profile is
// the running one, the new settings apply at once.
func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request, id string) {
	if config.IsReservedProfileID(id) {
		http.Error(w, "Built-in profiles are read-only; duplicate one to customise it", http.StatusForbidden)
		return
	}
	var req profileRequest
	if !readProfileRequest(w, r, &req) {
		return
	}
	sw, path, ok := s.profileStateOr503(w)
	if !ok {
		return
	}
	if req.ID != "" && req.ID != id {
		writeJSON(w, http.StatusUnprocessableEntity, profileProblem{
			Error:    "profile is invalid",
			Errors:   []config.Issue{{Field: "id", Message: "cannot be changed"}},
			Warnings: []config.Issue{},
		})
		return
	}
	s.profilesMu.Lock()
	defer s.profilesMu.Unlock()

	cfg, ok := loadForWrite(w, path)
	if !ok {
		return
	}
	i := customIndex(cfg.Profiles, id)
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	p := req.Profile
	p.ID = id
	p.BuiltIn = false
	p.Normalize()
	if !allowSave(w, cfg.CheckCandidate(p, id), req.Override) {
		return
	}
	cfg.Profiles[i] = p
	if !s.saveProfiles(w, path, cfg) {
		return
	}
	if sw.Current().ID == id {
		if err := applyIfChanged(sw, p); err != nil {
			http.Error(w, "Saved, but the profile could not be applied: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, s.listProfiles())
}

// deleteProfile removes a custom profile. The running profile can't be deleted;
// activate another one first.
func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request, id string) {
	if config.IsReservedProfileID(id) {
		http.Error(w, "Built-in profiles can't be deleted", http.StatusForbidden)
		return
	}
	if !profileRequestAllowed(w, r) {
		return
	}
	sw, path, ok := s.profileStateOr503(w)
	if !ok {
		return
	}
	s.profilesMu.Lock()
	defer s.profilesMu.Unlock()

	cfg, ok := loadForWrite(w, path)
	if !ok {
		return
	}
	i := customIndex(cfg.Profiles, id)
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	if id == cfg.ActiveProfile || id == sw.Current().ID {
		http.Error(w, "The active profile can't be deleted; activate another profile first", http.StatusConflict)
		return
	}
	cfg.Profiles = slices.Delete(cfg.Profiles, i, i+1)
	if !s.saveProfiles(w, path, cfg) {
		return
	}
	writeJSON(w, http.StatusOK, s.listProfiles())
}

// activateProfile makes a profile the running one and records the choice in
// config.json.
func (s *Server) activateProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !profileRequestAllowed(w, r) {
		return
	}
	sw, path, ok := s.profileStateOr503(w)
	if !ok {
		return
	}
	s.profilesMu.Lock()
	defer s.profilesMu.Unlock()

	cfg, ok := loadForWrite(w, path)
	if !ok {
		return
	}
	p, found := cfg.FindProfile(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	cfg.ActiveProfile = id
	if !s.saveProfiles(w, path, cfg) {
		return
	}
	if err := applyIfChanged(sw, p); err != nil {
		http.Error(w, "Saved, but the profile could not be applied: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.listProfiles())
}

// handleProfilesValidate checks a profile the way saving it would, without
// saving it. The response includes the load estimate the editor shows.
func (s *Server) handleProfilesValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req profileRequest
	if !readProfileRequest(w, r, &req) {
		return
	}
	cfg := config.Config{Profiles: s.customProfiles()}
	p := req.Profile
	if p.ID == "" {
		p.ID = cfg.NewProfileID(p.Name)
	}
	replacing := ""
	if q, found := cfg.FindProfile(p.ID); found && !q.BuiltIn {
		replacing = p.ID
	}
	p.BuiltIn = false
	p.Normalize()
	chk := cfg.CheckCandidate(p, replacing)
	writeJSON(w, http.StatusOK, validateResponse{
		Valid:    len(chk.Errors) == 0,
		Errors:   issues(chk.Errors),
		Warnings: issues(chk.Warnings),
		Estimate: p.Estimate(),
	})
}

// handleProfilesTestHosts probes every host of a profile once, so a typo shows
// before the profile is saved. Each host is probed with its layer's timeout.
func (s *Server) handleProfilesTestHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req profileRequest
	if !readProfileRequest(w, r, &req) {
		return
	}
	p := req.Profile
	p.Normalize()
	targets := probeTargets(p)
	if len(targets) > config.LimitHostsPerProf {
		http.Error(w, fmt.Sprintf("Test at most %d hosts at a time", config.LimitHostsPerProf), http.StatusUnprocessableEntity)
		return
	}

	results := make([]hostTestResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = hostResult(t, s.probeHost(p, t, uint64(i)))
		}()
	}
	wg.Wait()

	notes := []string{}
	if p.Targets.DNSIncludeSystem {
		notes = append(notes, "System DNS resolvers are found at run time and are not tested.")
	}
	writeJSON(w, http.StatusOK, testHostsResponse{Results: results, Notes: notes})
}

// handleProfilesReload applies a hand edit to config.json without a restart.
func (s *Server) handleProfilesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !profileRequestAllowed(w, r) {
		return
	}
	warnings, err := s.ReloadProfiles()
	switch {
	case errors.Is(err, errNoProfiles):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, reloadResponse{profilesResponse: s.listProfiles(), LoadWarnings: warnings})
}

// profileState returns the switcher and config path set by SetProfiles.
func (s *Server) profileState() (*switcher.Switcher, string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.profiles == nil {
		return nil, "", errNoProfiles
	}
	return s.profiles, s.profilesPath, nil
}

// profileStateOr503 is profileState for the routes that change profiles. It
// answers 503 and reports false when no switcher was set.
func (s *Server) profileStateOr503(w http.ResponseWriter) (*switcher.Switcher, string, bool) {
	sw, path, err := s.profileState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return nil, "", false
	}
	return sw, path, true
}

// activeProfile is the profile the monitor runs, or Standard before SetProfiles.
func (s *Server) activeProfile() config.Profile {
	s.lock.Lock()
	sw := s.profiles
	s.lock.Unlock()
	if sw == nil {
		return config.Standard()
	}
	return sw.Current()
}

// activeProfileSummary is the running profile as /api/status reports it.
func (s *Server) activeProfileSummary() map[string]any {
	p := s.activeProfile()
	return map[string]any{"id": p.ID, "name": p.Name, "mode": p.Mode}
}

// listProfiles reports every profile with the running one marked, and the limits.
func (s *Server) listProfiles() profilesResponse {
	active := s.activeProfile()
	all := config.Config{Profiles: s.customProfiles()}.AllProfiles()
	views := make([]profileView, 0, len(all))
	for _, p := range all {
		views = append(views, profileViewOf(p, active.ID))
	}
	return profilesResponse{ActiveProfile: active.ID, Profiles: views, Limits: profileLimitsView}
}

func profileViewOf(p config.Profile, active string) profileView {
	return profileView{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Mode:        p.Mode,
		BuiltIn:     p.BuiltIn,
		Active:      p.ID == active,
		Intervals:   p.Intervals,
		TimeoutsMS:  p.TimeoutsMS,
		Targets:     p.Targets,
		Estimate:    p.Estimate(),
		Warnings:    issues(p.Validate().Warnings),
	}
}

// customProfiles is a copy of the custom profiles as last loaded or saved.
func (s *Server) customProfiles() []config.Profile {
	s.lock.Lock()
	defer s.lock.Unlock()
	return cloneProfiles(s.custom)
}

func (s *Server) setCustom(list []config.Profile) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.custom = cloneProfiles(list)
}

// saveProfiles writes cfg to path and updates the server's list of custom
// profiles to match. It answers 500 and reports false if the write fails.
func (s *Server) saveProfiles(w http.ResponseWriter, path string, cfg config.Config) bool {
	if err := config.SaveConfig(path, cfg); err != nil {
		http.Error(w, "Could not save config.json: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	s.setCustom(cfg.Profiles)
	return true
}

// readProfileRequest checks that a profile request is a same-origin JSON
// request, then decodes its body. It answers the error itself and reports false
// when the request must stop.
func readProfileRequest(w http.ResponseWriter, r *http.Request, req *profileRequest) bool {
	if !profileRequestAllowed(w, r) {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		http.Error(w, "Invalid profile JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// profileRequestAllowed refuses a profile request that isn't JSON from the
// dashboard's own origin, so other pages can't change profiles or start probes.
// The CSRF token is checked by the security middleware.
func profileRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType != "application/json" {
		http.Error(w, "Profile requests must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	if r.Header.Get("Origin") != "http://"+r.Host {
		http.Error(w, "Profile requests must come from the dashboard", http.StatusForbidden)
		return false
	}
	return true
}

// allowSave answers 422 and reports false when a profile can't be saved: it has
// errors, or warnings the request didn't override.
func allowSave(w http.ResponseWriter, chk config.Check, override bool) bool {
	switch {
	case len(chk.Errors) > 0:
		writeJSON(w, http.StatusUnprocessableEntity, profileProblem{
			Error:    "profile is invalid",
			Errors:   issues(chk.Errors),
			Warnings: issues(chk.Warnings),
		})
		return false
	case len(chk.Warnings) > 0 && !override:
		writeJSON(w, http.StatusUnprocessableEntity, profileProblem{
			Error:         "profile is over a safety limit; send override: true to save it anyway",
			Errors:        []config.Issue{},
			Warnings:      chk.Warnings,
			NeedsOverride: true,
		})
		return false
	}
	return true
}

// loadForWrite reads config.json just before a change, so a hand edit isn't
// overwritten. A file that can't be parsed is never rewritten: it answers 409.
func loadForWrite(w http.ResponseWriter, path string) (config.Config, bool) {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		http.Error(w, "config.json could not be read, so nothing was changed. Fix the file, then reload: "+err.Error(), http.StatusConflict)
		return cfg, false
	}
	return cfg, true
}

// applyIfChanged switches the monitor to p unless it already runs exactly p, so
// saving or reloading an unchanged profile doesn't reset the detector.
func applyIfChanged(sw *switcher.Switcher, p config.Profile) error {
	p = p.Clone()
	p.Normalize()
	if reflect.DeepEqual(sw.Current(), p) {
		return nil
	}
	return sw.Apply(p)
}

// probeTargets lists the configured hosts of p as the registry would probe
// them. System DNS resolvers are found at run time, so they are not listed.
func probeTargets(p config.Profile) []probe.Target {
	var out []probe.Target
	for _, a := range p.Targets.WANICMP {
		out = append(out, probe.Target{Layer: probe.LayerWANICMP, Address: a})
	}
	for _, a := range p.Targets.WANTCP {
		out = append(out, probe.Target{Layer: probe.LayerWANTCP, Address: a})
	}
	for _, a := range p.Targets.DNS {
		out = append(out, probe.Target{Layer: probe.LayerDNS, Address: a})
	}
	for _, h := range p.Targets.HTTP {
		out = append(out, probe.Target{Layer: probe.LayerHTTP, Address: h.URL, Expected: h.Status, BodyPrefix: h.BodyPrefix})
	}
	return out
}

// probeHost runs one probe of t, using the timeout its layer has in p.
func (s *Server) probeHost(p config.Profile, t probe.Target, seq uint64) probe.ProbeResult {
	ms := func(v int) time.Duration { return time.Duration(v) * time.Millisecond }
	switch t.Layer {
	case probe.LayerWANICMP:
		return probe.ProbeICMP(t, ms(p.TimeoutsMS.ICMP), seq)
	case probe.LayerWANTCP:
		return probe.ProbeTCP(t, ms(p.TimeoutsMS.TCP), seq)
	case probe.LayerDNS:
		return probe.ProbeDNS(t, p.Targets.DNSQueryName, ms(p.TimeoutsMS.DNS), seq)
	default:
		return probe.ProbeHTTP(t, ms(p.TimeoutsMS.HTTP), seq, s.version)
	}
}

// hostResult turns a probe of t into the answer the editor shows.
func hostResult(t probe.Target, res probe.ProbeResult) hostTestResult {
	out := hostTestResult{
		Layer:   string(t.Layer),
		Address: t.Address,
		OK:      res.OK,
		RTTMS:   float64(res.RTTUS) / 1000,
		Status:  res.HTTPStatus,
	}
	if !res.OK {
		out.Error = res.ErrCode.String()
		if res.ErrText != "" {
			out.Error += ": " + res.ErrText
		}
	}
	return out
}

// customIndex finds the custom profile with id in list, or returns -1.
func customIndex(list []config.Profile, id string) int {
	return slices.IndexFunc(list, func(p config.Profile) bool { return p.ID == id })
}

func cloneProfiles(list []config.Profile) []config.Profile {
	out := make([]config.Profile, len(list))
	for i, p := range list {
		out[i] = p.Clone()
	}
	return out
}

// issues returns list, or an empty list, so the JSON holds an array and not null.
func issues(list []config.Issue) []config.Issue {
	if list == nil {
		return []config.Issue{}
	}
	return list
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
