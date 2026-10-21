package updater_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/updater"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		v1   string
		v2   string
		want int
	}{
		{"0.1.0", "0.1.0", 0},
		{"v0.1.0", "0.1.0", 0},
		{"0.1.0", "0.2.0", -1},
		{"0.2.0", "0.1.0", 1},
		{"0.1.0-dev", "0.1.0", -1},
		{"0.1.0", "0.1.0-dev", 1},
		{"1.0.0", "1.10.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.4", "v1.2.3", 1},
	}

	for _, c := range cases {
		got := updater.CompareVersions(c.v1, c.v2)
		if (c.want == 0 && got != 0) || (c.want < 0 && got >= 0) || (c.want > 0 && got <= 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", c.v1, c.v2, got, c.want)
		}
	}
}

func TestSelectAsset(t *testing.T) {
	assets := []updater.ReleaseAsset{
		{Name: "netscan-linux-amd64.tar.gz", DownloadURL: "https://example.com/linux.tar.gz", Size: 100},
		{Name: "netscan-windows-amd64.zip", DownloadURL: "https://example.com/win.zip", Size: 200},
		{Name: "netscan.exe", DownloadURL: "https://example.com/netscan.exe", Size: 300},
	}

	best, ok := updater.SelectAsset(assets, "windows", "amd64")
	if !ok {
		t.Fatal("expected asset to be selected")
	}
	if best.Name != "netscan-windows-amd64.zip" {
		t.Fatalf("expected netscan-windows-amd64.zip, got %s", best.Name)
	}

	exeOnly := []updater.ReleaseAsset{
		{Name: "netscan.exe", DownloadURL: "https://example.com/netscan.exe", Size: 300},
	}
	bestExe, ok := updater.SelectAsset(exeOnly, "windows", "amd64")
	if !ok || bestExe.Name != "netscan.exe" {
		t.Fatalf("expected netscan.exe, got %+v", bestExe)
	}

	none := []updater.ReleaseAsset{
		{Name: "README.md", DownloadURL: "https://example.com/readme.md", Size: 10},
	}
	_, ok = updater.SelectAsset(none, "windows", "amd64")
	if ok {
		t.Fatal("expected no asset to match")
	}
}

func TestFetchLatestRelease(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := updater.Release{
			TagName:     "v0.2.0",
			Name:        "Release v0.2.0",
			Body:        "Fixes micro-drops",
			HTMLURL:     "https://github.com/aaronburt/netscan/releases/tag/v0.2.0",
			PublishedAt: time.Now().UTC(),
			Assets: []updater.ReleaseAsset{
				{
					Name:        "netscan-windows-amd64.zip",
					DownloadURL: "https://example.com/asset.zip",
					Size:        1024,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rel)
	}))
	defer ts.Close()

	rel, err := updater.FetchLatestRelease(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("FetchLatestRelease failed: %v", err)
	}

	if rel.Version != "0.2.0" {
		t.Fatalf("expected version 0.2.0, got %s", rel.Version)
	}
	if rel.AssetName != "netscan-windows-amd64.zip" {
		t.Fatalf("expected netscan-windows-amd64.zip, got %s", rel.AssetName)
	}
	if rel.AssetURL != "https://example.com/asset.zip" {
		t.Fatalf("expected asset url https://example.com/asset.zip, got %s", rel.AssetURL)
	}
}

func createFakePEPayload() []byte {
	buf := make([]byte, 600*1024)
	buf[0] = 'M'
	buf[1] = 'Z'
	return buf
}

func TestDownloadAndExtractZip(t *testing.T) {
	payload := createFakePEPayload()

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, err := zw.Create("netscan.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBuf.Bytes())
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	var progressCalled bool
	extractedPath, err := updater.DownloadAndExtract(context.Background(), ts.Client(), ts.URL, tmpDir, "", func(down, tot int64) {
		progressCalled = true
	})
	if err != nil {
		t.Fatalf("DownloadAndExtract failed: %v", err)
	}
	defer os.Remove(extractedPath)

	if !progressCalled {
		t.Fatal("expected progress callback to be called")
	}

	if err := updater.ValidateExecutable(extractedPath); err != nil {
		t.Fatalf("ValidateExecutable failed: %v", err)
	}
}

func TestChecksumVerification(t *testing.T) {
	payload := createFakePEPayload()

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, err := zw.Create("netscan.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipBytes := zipBuf.Bytes()
	h := sha256.Sum256(zipBytes)
	correctHash := hex.EncodeToString(h[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()

	validPath, err := updater.DownloadAndExtract(context.Background(), ts.Client(), ts.URL, tmpDir, correctHash, nil)
	if err != nil {
		t.Fatalf("expected valid checksum to succeed, got: %v", err)
	}
	defer os.Remove(validPath)

	badHash := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = updater.DownloadAndExtract(context.Background(), ts.Client(), ts.URL, tmpDir, badHash, nil)
	if err == nil {
		t.Fatal("expected download to fail with checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected 'checksum mismatch' error, got %v", err)
	}
}

func TestParseExpectedChecksum(t *testing.T) {
	manifest := `
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  netscan.exe
a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123 *netscan-windows-amd64.zip
`
	hash := updater.ParseExpectedChecksum(manifest, "netscan-windows-amd64.zip")
	if hash != "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123" {
		t.Fatalf("unexpected parsed hash: %s", hash)
	}

	single := "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123\n"
	hashSingle := updater.ParseExpectedChecksum(single, "netscan.exe")
	if hashSingle != "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123" {
		t.Fatalf("unexpected single hash: %s", hashSingle)
	}
}

func TestValidateExecutableErrors(t *testing.T) {
	tmpDir := t.TempDir()

	smallFile := filepath.Join(tmpDir, "small.exe")
	_ = os.WriteFile(smallFile, []byte("MZsmall"), 0755)
	if err := updater.ValidateExecutable(smallFile); err == nil {
		t.Fatal("expected error for file < 512KB")
	}

	notMZ := filepath.Join(tmpDir, "bad.exe")
	badData := make([]byte, 600*1024)
	badData[0] = 'N'
	badData[1] = 'O'
	_ = os.WriteFile(notMZ, badData, 0755)
	if err := updater.ValidateExecutable(notMZ); err == nil {
		t.Fatal("expected error for missing MZ header")
	}
}

func TestManagerCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := updater.Release{
			TagName: "v0.3.0",
			Name:    "Release v0.3.0",
			Assets: []updater.ReleaseAsset{
				{
					Name:        "netscan-windows-amd64.exe",
					DownloadURL: "https://example.com/netscan.exe",
					Size:        2000000,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rel)
	}))
	defer ts.Close()

	mgr := updater.NewManager(ts.URL, "0.1.0", nil)
	mgr.SetHTTPClient(ts.Client())

	res, err := mgr.Check(context.Background())
	if err != nil {
		t.Fatalf("manager check failed: %v", err)
	}

	if !res.UpdateAvailable {
		t.Fatal("expected update to be available")
	}

	status := mgr.Status()
	if status.State != updater.StateAvailable {
		t.Fatalf("expected state available, got %s", status.State)
	}
	if status.LatestVersion != "0.3.0" {
		t.Fatalf("expected latest version 0.3.0, got %s", status.LatestVersion)
	}
}
