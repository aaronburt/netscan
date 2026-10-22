package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func smokeGet(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, body
}

func smokeCSRFToken(t *testing.T, baseURL string) string {
	t.Helper()
	_, body := smokeGet(t, baseURL+"/")
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "csrf-token") {
			if parts := strings.Split(line, `content="`); len(parts) > 1 {
				return strings.Split(parts[1], `"`)[0]
			}
		}
	}
	t.Fatal("csrf token not found in index")
	return ""
}

func TestSmokeReadEndpoints(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	jsonEndpoints := []string{
		"/api/status",
		"/api/events",
		"/api/events?limit=5&kind=outage",
		"/api/samples",
		"/api/samples?failed_only=true&limit=5",
		"/api/rollups",
		"/api/targets",
		"/api/update/status",
		"/api/export/rollups.json",
	}
	for _, path := range jsonEndpoints {
		res, body := smokeGet(t, baseURL+path)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, res.StatusCode)
		}
		if !json.Valid(body) {
			t.Fatalf("%s: response is not valid JSON: %s", path, body)
		}
	}

	for _, path := range []string{"/api/export/events.csv", "/api/export/samples.csv", "/api/export/rollups.csv"} {
		res, body := smokeGet(t, baseURL+path)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Fatalf("%s: content type %q", path, ct)
		}
		if len(body) == 0 {
			t.Fatalf("%s: empty csv, expected a header row", path)
		}
	}

	res, body := smokeGet(t, baseURL+"/app.js")
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "calcState") {
		t.Fatalf("/app.js not served correctly: status %d", res.StatusCode)
	}

	var status struct {
		Version  string `json:"version"`
		Snapshot struct {
			StateString string `json:"state_string"`
		} `json:"snapshot"`
	}
	_, body = smokeGet(t, baseURL+"/api/status")
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if status.Version != "test" || status.Snapshot.StateString != "HEALTHY" {
		t.Fatalf("unexpected status payload: %+v", status)
	}
}

func TestSmokeEventDetailErrors(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	if res, _ := smokeGet(t, baseURL+"/api/events/not-a-number"); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad id: status %d, want 400", res.StatusCode)
	}
	if res, _ := smokeGet(t, baseURL+"/api/events/999999"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing event: status %d, want 404", res.StatusCode)
	}
}

func TestSmokePauseAndResume(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	token := smokeCSRFToken(t, baseURL)
	client := &http.Client{Timeout: 3 * time.Second}
	for _, path := range []string{"/api/pause", "/api/resume"} {
		req, _ := http.NewRequest(http.MethodPost, baseURL+path, nil)
		req.Header.Set("X-NetScan-Token", token)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST %s: status %d", path, res.StatusCode)
		}
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/pause", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without token: status %d, want 403", res.StatusCode)
	}
}
