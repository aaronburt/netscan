package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
)

// profileJSON is a profile as the dashboard sends it.
type profileJSON struct {
	config.Profile
	Override bool `json:"override,omitempty"`
}

// listedProfile, profilesBody and friends are the parts of the API the tests read.
type listedProfile struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Mode     string              `json:"mode"`
	BuiltIn  bool                `json:"built_in"`
	Active   bool                `json:"active"`
	Estimate config.LoadEstimate `json:"estimate"`
	Warnings []config.Issue      `json:"warnings"`
}

type profilesBody struct {
	ActiveProfile string          `json:"active_profile"`
	Profiles      []listedProfile `json:"profiles"`
	Limits        struct {
		CustomProfiles int `json:"custom_profiles"`
	} `json:"limits"`
}

type problemBody struct {
	Error         string         `json:"error"`
	Errors        []config.Issue `json:"errors"`
	Warnings      []config.Issue `json:"warnings"`
	NeedsOverride bool           `json:"needs_override"`
}

type validateBody struct {
	Valid    bool                `json:"valid"`
	Errors   []config.Issue      `json:"errors"`
	Estimate config.LoadEstimate `json:"estimate"`
}

type hostResultBody struct {
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

type testHostsBody struct {
	Results []hostResultBody `json:"results"`
	Notes   []string         `json:"notes"`
}

type runningProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}

// newProfile is a valid custom profile with the Standard polling settings.
func newProfile(name, id string) profileJSON {
	p := config.Standard()
	p.ID = id
	p.Name = name
	p.BuiltIn = false
	return profileJSON{Profile: p}
}

// csrfToken reads the dashboard's CSRF token from its index page.
func csrfToken(t *testing.T, base string) string {
	t.Helper()
	res, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	_, after, found := strings.Cut(string(body), `<meta name="csrf-token" content="`)
	token, _, ok := strings.Cut(after, `"`)
	if !found || !ok {
		t.Fatal("missing csrf token in index html")
	}
	return token
}

// send makes a request the way the dashboard does: JSON from its own origin
// with the CSRF token. A nil body sends none.
func send(t *testing.T, base, method, path, token string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("X-NetScan-Token", token)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

// expect checks a response's status and returns its body.
func expect(t *testing.T, res *http.Response, status int) []byte {
	t.Helper()
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", res.StatusCode, status, body)
	}
	return body
}

func mustDecode(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

func listProfiles(t *testing.T, base string) profilesBody {
	t.Helper()
	res, err := http.Get(base + "/api/profiles")
	if err != nil {
		t.Fatal(err)
	}
	var list profilesBody
	mustDecode(t, expect(t, res, http.StatusOK), &list)
	return list
}

// findProfile returns the listed profile with id, or nil.
func findProfile(list profilesBody, id string) *listedProfile {
	for i := range list.Profiles {
		if list.Profiles[i].ID == id {
			return &list.Profiles[i]
		}
	}
	return nil
}

// running reads the profile /api/status reports as running.
func running(t *testing.T, base string) runningProfile {
	t.Helper()
	res, err := http.Get(base + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Active runningProfile `json:"active_profile"`
	}
	mustDecode(t, expect(t, res, http.StatusOK), &status)
	return status.Active
}

// onDisk reports whether config.json holds a profile with id.
func onDisk(t *testing.T, id string) bool {
	t.Helper()
	cfg, err := config.LoadConfig(config.ConfigPath())
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	_, found := cfg.FindProfile(id)
	return found
}

func hasField(issues []config.Issue, field string) bool {
	for _, i := range issues {
		if i.Field == field {
			return true
		}
	}
	return false
}

func TestProfilesListBuiltIns(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()

	list := listProfiles(t, base)
	if list.ActiveProfile != config.ProfileStandard {
		t.Fatalf("active = %q, want standard", list.ActiveProfile)
	}
	for _, id := range []string{config.ProfileStandard, config.ProfileAggressive, config.ProfileLax} {
		p := findProfile(list, id)
		if p == nil || !p.BuiltIn {
			t.Fatalf("built-in %s missing or not marked built_in", id)
		}
		if len(p.Warnings) > 0 || p.Estimate.RowsPerDay <= 0 {
			t.Errorf("%s: warnings %v, rows/day %d", id, p.Warnings, p.Estimate.RowsPerDay)
		}
		if p.Active != (id == config.ProfileStandard) {
			t.Errorf("%s: active = %v", id, p.Active)
		}
	}
	if list.Limits.CustomProfiles != config.LimitCustomProfiles {
		t.Errorf("limits.custom_profiles = %d", list.Limits.CustomProfiles)
	}
}

func TestProfileLifecycle(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	// With no id, the id comes from the name.
	var list profilesBody
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Office Wi-Fi", "")), http.StatusCreated), &list)
	if p := findProfile(list, "office-wi-fi"); p == nil || p.BuiltIn {
		t.Fatalf("created profile not listed as custom: %+v", p)
	}
	if !onDisk(t, "office-wi-fi") {
		t.Fatal("created profile was not written to config.json")
	}

	// The name "Standard" is taken, so the id gets a suffix.
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Standard", "")), http.StatusCreated), &list)
	if findProfile(list, "standard-2") == nil {
		t.Fatal("expected the id standard-2")
	}

	// Edit by id: the name changes and the id stays.
	mustDecode(t, expect(t, send(t, base, http.MethodPut, "/api/profiles/office-wi-fi", token, newProfile("Office", "")), http.StatusOK), &list)
	if p := findProfile(list, "office-wi-fi"); p == nil || p.Name != "Office" {
		t.Fatalf("edit not applied: %+v", p)
	}

	expect(t, send(t, base, http.MethodDelete, "/api/profiles/office-wi-fi", token, nil), http.StatusOK)
	if findProfile(listProfiles(t, base), "office-wi-fi") != nil || onDisk(t, "office-wi-fi") {
		t.Fatal("deleted profile is still listed or on disk")
	}
}

func TestProfileRefusals(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	// A profile needs two of TCP, DNS and HTTP.
	lonely := newProfile("Lonely", "lonely")
	lonely.Targets.DNS = nil
	lonely.Targets.HTTP = nil
	var problem problemBody
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, lonely), http.StatusUnprocessableEntity), &problem)
	if !hasField(problem.Errors, "targets") {
		t.Fatalf("errors = %+v, want one on targets", problem.Errors)
	}

	// A 500ms TCP period is under the 1s floor, so the profile needs override.
	chatty := newProfile("Chatty", "chatty")
	chatty.Mode = config.ModeParallel
	chatty.Intervals.NormalMS = 250
	chatty.Intervals.FastMS = 250
	chatty.Intervals.WANTCPMS = 500
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, chatty), http.StatusUnprocessableEntity), &problem)
	if !problem.NeedsOverride || len(problem.Warnings) == 0 {
		t.Fatalf("want needs_override with warnings, got %+v", problem)
	}
	if findProfile(listProfiles(t, base), "chatty") != nil {
		t.Fatal("a refused profile was saved")
	}

	chatty.Override = true
	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, chatty), http.StatusCreated)
	if p := findProfile(listProfiles(t, base), "chatty"); p == nil || len(p.Warnings) == 0 {
		t.Fatal("an overridden profile should keep its warnings")
	}

	// Built-ins are read-only, and unknown ids are not found.
	expect(t, send(t, base, http.MethodPut, "/api/profiles/standard", token, newProfile("Mine", "standard")), http.StatusForbidden)
	expect(t, send(t, base, http.MethodDelete, "/api/profiles/lax", token, nil), http.StatusForbidden)
	expect(t, send(t, base, http.MethodPut, "/api/profiles/nope", token, newProfile("Nope", "nope")), http.StatusNotFound)
	expect(t, send(t, base, http.MethodDelete, "/api/profiles/nope", token, nil), http.StatusNotFound)

	// A taken id, a route word as id and a changed id are refused.
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Again", "chatty")), http.StatusUnprocessableEntity), &problem)
	if !hasField(problem.Errors, "id") {
		t.Fatalf("taken id: errors = %+v", problem.Errors)
	}
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Reload", "reload")), http.StatusUnprocessableEntity), &problem)
	if !hasField(problem.Errors, "id") {
		t.Fatalf("route word as id: errors = %+v", problem.Errors)
	}
	mustDecode(t, expect(t, send(t, base, http.MethodPut, "/api/profiles/chatty", token, newProfile("Chatty", "other")), http.StatusUnprocessableEntity), &problem)
	if !hasField(problem.Errors, "id") {
		t.Fatalf("changed id: errors = %+v", problem.Errors)
	}
}

func TestProfileActivate(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Night", "night")), http.StatusCreated)
	expect(t, send(t, base, http.MethodPost, "/api/profiles/night/activate", token, nil), http.StatusOK)
	if got := running(t, base); got.ID != "night" {
		t.Fatalf("running = %q, want night", got.ID)
	}
	cfg, err := config.LoadConfig(config.ConfigPath())
	if err != nil || cfg.ActiveProfile != "night" {
		t.Fatalf("config.json active = %q (%v), want night", cfg.ActiveProfile, err)
	}

	// Editing the running profile applies its new settings at once.
	edited := newProfile("Night", "night")
	edited.Mode = config.ModeParallel
	expect(t, send(t, base, http.MethodPut, "/api/profiles/night", token, edited), http.StatusOK)
	if got := running(t, base); got.Mode != config.ModeParallel {
		t.Fatalf("running mode = %q after editing, want parallel", got.Mode)
	}

	// The running profile can't be deleted.
	expect(t, send(t, base, http.MethodDelete, "/api/profiles/night", token, nil), http.StatusConflict)

	expect(t, send(t, base, http.MethodPost, "/api/profiles/lax/activate", token, nil), http.StatusOK)
	if got := running(t, base); got.ID != config.ProfileLax {
		t.Fatalf("running = %q, want lax", got.ID)
	}
	expect(t, send(t, base, http.MethodDelete, "/api/profiles/night", token, nil), http.StatusOK)

	expect(t, send(t, base, http.MethodPost, "/api/profiles/nope/activate", token, nil), http.StatusNotFound)
	res, err := http.Get(base + "/api/profiles/lax/activate")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, res, http.StatusMethodNotAllowed)
}

func TestProfileGuards(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	// raw sends a request with exactly the given headers and returns its status.
	raw := func(method, path, contentType, origin, tok, body string) int {
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if tok != "" {
			req.Header.Set("X-NetScan-Token", tok)
		}
		res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	body := `{"name":"Guarded","id":"guarded"}`

	if got := raw(http.MethodPost, "/api/profiles", "text/plain", base, token, body); got != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: status %d, want 415", got)
	}
	if got := raw(http.MethodPost, "/api/profiles", "application/json", "http://evil.example", token, body); got != http.StatusForbidden {
		t.Errorf("foreign origin: status %d, want 403", got)
	}
	if got := raw(http.MethodPost, "/api/profiles", "application/json", "", token, body); got != http.StatusForbidden {
		t.Errorf("no origin: status %d, want 403", got)
	}
	if got := raw(http.MethodPut, "/api/profiles/chatty", "application/json", base, "", body); got != http.StatusForbidden {
		t.Errorf("PUT without token: status %d, want 403", got)
	}
	if got := raw(http.MethodDelete, "/api/profiles/chatty", "application/json", base, "", ""); got != http.StatusForbidden {
		t.Errorf("DELETE without token: status %d, want 403", got)
	}
	if got := raw(http.MethodGet, "/api/profiles", "", "", "", ""); got != http.StatusOK {
		t.Errorf("GET without origin or token: status %d, want 200", got)
	}

	// A misspelt field is refused rather than ignored.
	typo := map[string]any{"name": "Typo", "intervals": map[string]any{"normal_mss": 1000}}
	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, typo), http.StatusBadRequest)
}

func TestProfileValidate(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	var check validateBody
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/validate", token, newProfile("Check", "check")), http.StatusOK), &check)
	if !check.Valid || check.Estimate.RowsPerDay <= 0 {
		t.Fatalf("valid profile reported as %+v", check)
	}
	if _, err := os.Stat(config.ConfigPath()); !os.IsNotExist(err) {
		t.Fatal("validate saved something")
	}

	lonely := newProfile("Lonely", "lonely")
	lonely.Targets.DNS = nil
	lonely.Targets.HTTP = nil
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/validate", token, lonely), http.StatusOK), &check)
	if check.Valid || !hasField(check.Errors, "targets") {
		t.Fatalf("one-layer profile reported as %+v", check)
	}

	// An id that belongs to a custom profile is an edit of it, so it isn't taken.
	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Keep", "keep")), http.StatusCreated)
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/validate", token, newProfile("Keep", "keep")), http.StatusOK), &check)
	if !check.Valid {
		t.Fatalf("editing an existing profile reported as %+v", check)
	}

	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/validate", token, newProfile("Validate", "validate")), http.StatusOK), &check)
	if check.Valid || !hasField(check.Errors, "id") {
		t.Fatalf("route word as id reported as %+v", check)
	}
}

func TestProfileTestHosts(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer web.Close()

	candidate := newProfile("Probe", "probe")
	candidate.TimeoutsMS.DNS = 200
	candidate.Targets = config.TargetsConfig{
		WANICMP: []string{"not-an-ip"},
		WANTCP:  []string{open.Addr().String(), closedAddr},
		DNS:     []string{"127.0.0.1:1"},
		HTTP:    []config.HTTPTargetConfig{{URL: web.URL, Status: http.StatusNoContent}},
	}

	var result testHostsBody
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/test-hosts", token, candidate), http.StatusOK), &result)
	if len(result.Results) != 5 {
		t.Fatalf("got %d results, want one per host", len(result.Results))
	}
	byAddress := map[string]hostResultBody{}
	for _, r := range result.Results {
		byAddress[r.Address] = r
	}
	if r := byAddress[open.Addr().String()]; !r.OK {
		t.Errorf("open port: %+v", r)
	}
	if r := byAddress[closedAddr]; r.OK || r.Error == "" {
		t.Errorf("closed port should fail with an error: %+v", r)
	}
	if r := byAddress[web.URL]; !r.OK || r.Status != http.StatusNoContent {
		t.Errorf("HTTP host: %+v", r)
	}
	if r := byAddress["not-an-ip"]; r.OK || !strings.Contains(r.Error, "invalid ip address") {
		t.Errorf("ICMP host with a name: %+v", r)
	}
	if r := byAddress["127.0.0.1:1"]; r.OK {
		t.Errorf("DNS host with nothing listening should fail: %+v", r)
	}
	if len(result.Notes) != 0 {
		t.Errorf("notes = %v, want none", result.Notes)
	}

	candidate.Targets.DNSIncludeSystem = true
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/test-hosts", token, candidate), http.StatusOK), &result)
	if len(result.Notes) != 1 {
		t.Errorf("notes = %v, want the system DNS note", result.Notes)
	}

	var many []string
	for i := 0; i <= config.LimitHostsPerProf; i++ {
		many = append(many, fmt.Sprintf("127.0.0.1:%d", 1000+i))
	}
	candidate.Targets.WANTCP = many
	expect(t, send(t, base, http.MethodPost, "/api/profiles/test-hosts", token, candidate), http.StatusUnprocessableEntity)
}

func TestProfileReloadPicksUpHandEdit(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	// A hand edit that adds a profile and makes it the active one.
	cfg := config.DefaultConfig()
	cfg.Profiles = []config.Profile{newProfile("Hand made", "hand-made").Profile}
	cfg.ActiveProfile = "hand-made"
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ConfigPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var reloaded struct {
		LoadWarnings []string `json:"load_warnings"`
	}
	mustDecode(t, expect(t, send(t, base, http.MethodPost, "/api/profiles/reload", token, nil), http.StatusOK), &reloaded)
	if reloaded.LoadWarnings == nil {
		t.Error("load_warnings should be an empty list, not null")
	}
	if got := running(t, base); got.ID != "hand-made" {
		t.Fatalf("running = %q after reload, want hand-made", got.ID)
	}
	if findProfile(listProfiles(t, base), "hand-made") == nil {
		t.Fatal("reload did not list the hand-edited profile")
	}

	// A file that doesn't parse changes nothing.
	if err := os.WriteFile(config.ConfigPath(), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, send(t, base, http.MethodPost, "/api/profiles/reload", token, nil), http.StatusUnprocessableEntity)
	if got := running(t, base); got.ID != "hand-made" {
		t.Fatalf("running = %q after a broken reload, want hand-made", got.ID)
	}
}

func TestProfileWritesRefuseBrokenConfig(t *testing.T) {
	srv, base := setupTestServer(t)
	defer srv.Stop()
	token := csrfToken(t, base)

	broken := []byte("{ not json")
	if err := os.WriteFile(config.ConfigPath(), broken, 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Lost", "lost")), http.StatusConflict)
	if data, _ := os.ReadFile(config.ConfigPath()); string(data) != string(broken) {
		t.Fatal("a file that doesn't parse was rewritten")
	}
}

func TestProfilesNeedSetup(t *testing.T) {
	srv, base := setupServer(t, false)
	defer srv.Stop()
	token := csrfToken(t, base)

	if got := listProfiles(t, base).ActiveProfile; got != config.ProfileStandard {
		t.Fatalf("active = %q without a switcher, want standard", got)
	}
	expect(t, send(t, base, http.MethodPost, "/api/profiles", token, newProfile("Early", "early")), http.StatusServiceUnavailable)
	expect(t, send(t, base, http.MethodPost, "/api/profiles/reload", token, nil), http.StatusServiceUnavailable)
	if _, err := srv.ReloadProfiles(); err == nil {
		t.Fatal("ReloadProfiles without a switcher should fail")
	}
}
