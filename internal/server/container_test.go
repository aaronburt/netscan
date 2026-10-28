package server_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/updater"
)

func getIndex(t *testing.T, url string) string {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to get /: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read /: %v", err)
	}
	return string(body)
}

func TestIndexHidesUpdateMenuInContainer(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	mgr := updater.NewManager("aaronburt/netscan", "test", nil)
	mgr.SetContainer(true)
	srv.SetUpdaterManager(mgr)

	if body := getIndex(t, baseURL+"/"); !strings.Contains(body, `class="btn hidden" id="btn-update-menu"`) {
		t.Fatal("the update menu should be hidden in a container")
	}
}

func TestIndexShowsUpdateMenuOutsideContainer(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	srv.SetUpdaterManager(updater.NewManager("aaronburt/netscan", "test", nil))

	if body := getIndex(t, baseURL+"/"); !strings.Contains(body, `class="btn" id="btn-update-menu"`) {
		t.Fatal("the update menu should stay visible outside a container")
	}
}
