package updater_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aaronburt/netscan/internal/updater"
)

func releaseAssets() []updater.ReleaseAsset {
	return []updater.ReleaseAsset{
		{Name: "netscan.exe"},
		{Name: "updater.exe"},
		{Name: "netscan-windows-amd64.zip"},
		{Name: "netscan-installer.exe"},
		{Name: "netscan-linux-amd64.tar.gz"},
		{Name: "netscan-linux-arm64.tar.gz"},
		{Name: "checksums.txt"},
	}
}

func TestSelectAssetLinux(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		got, ok := updater.SelectAsset(releaseAssets(), "linux", arch)
		want := "netscan-linux-" + arch + ".tar.gz"
		if !ok || got.Name != want {
			t.Fatalf("linux/%s: got %q (ok=%v), want %q", arch, got.Name, ok, want)
		}
	}

	// No tarball for this arch: never fall back to a Windows package.
	assets := []updater.ReleaseAsset{{Name: "netscan.exe"}, {Name: "netscan-windows-amd64.zip"}, {Name: "netscan-linux-arm64.tar.gz"}}
	if got, ok := updater.SelectAsset(assets, "linux", "amd64"); ok {
		t.Fatalf("linux/amd64 selected %q", got.Name)
	}
}

func TestSelectAssetWindowsIgnoresTarballs(t *testing.T) {
	got, ok := updater.SelectAsset(releaseAssets(), "windows", "amd64")
	if !ok || got.Name != "netscan-windows-amd64.zip" {
		t.Fatalf("got %q (ok=%v), want netscan-windows-amd64.zip", got.Name, ok)
	}

	onlyLinux := []updater.ReleaseAsset{{Name: "netscan-linux-amd64.tar.gz"}, {Name: "netscan-linux-arm64.tar.gz"}, {Name: "checksums.txt"}}
	if got, ok := updater.SelectAsset(onlyLinux, "windows", "amd64"); ok {
		t.Fatalf("windows selected %q from a Linux-only release", got.Name)
	}
}

func makeTarGz(t *testing.T, files map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range order {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serve(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestDownloadAndExtractTarGz(t *testing.T) {
	binary := append([]byte("\x7fELF"), make([]byte, 600*1024)...)
	archive := makeTarGz(t, map[string][]byte{
		"netscan-linux-amd64/install.sh":      []byte("#!/bin/sh\n"),
		"netscan-linux-amd64/netscan.service": []byte("[Unit]\n"),
		"netscan-linux-amd64/netscan":         binary,
	}, []string{"netscan-linux-amd64/install.sh", "netscan-linux-amd64/netscan.service", "netscan-linux-amd64/netscan"})
	ts := serve(t, archive)

	dir := t.TempDir()
	sum := sha256.Sum256(archive)
	path, err := updater.DownloadAndExtract(context.Background(), ts.Client(), ts.URL, dir, hex.EncodeToString(sum[:]), nil)
	if err != nil {
		t.Fatalf("DownloadAndExtract: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binary) {
		t.Fatal("extracted file is not the netscan binary")
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("extracted binary is not executable: %v", fi.Mode())
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("extracted outside target dir: %s", path)
	}

	// Only the extracted binary remains: the download temp file is cleaned up.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file left in target dir, got %d", len(entries))
	}
}

func TestDownloadAndExtractTarGzWithoutBinary(t *testing.T) {
	archive := makeTarGz(t, map[string][]byte{"pkg/install.sh": []byte("x")}, []string{"pkg/install.sh"})
	ts := serve(t, archive)

	dir := t.TempDir()
	sum := sha256.Sum256(archive)
	if _, err := updater.DownloadAndExtract(context.Background(), ts.Client(), ts.URL, dir, hex.EncodeToString(sum[:]), nil); err == nil {
		t.Fatal("expected an error when the archive has no netscan binary")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("temp files left behind: %d", len(entries))
	}
}

func TestCanReplaceBinary(t *testing.T) {
	// The test binary lives in a writable temp dir.
	if !updater.CanReplaceBinary() {
		t.Skip("test binary directory is not writable")
	}
}
