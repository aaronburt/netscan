//go:build windows

package installer_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/installer"
)

func TestDefaultOptions(t *testing.T) {
	opts := installer.DefaultOptions()
	if opts.InstallDir == "" {
		t.Fatal("expected non-empty default install dir")
	}
	if !strings.HasSuffix(opts.InstallDir, "NetScan") {
		t.Fatalf("expected install dir ending in NetScan, got %s", opts.InstallDir)
	}
	if !opts.DesktopShortcut || !opts.StartMenuShortcut || !opts.RunAtStartup || !opts.LaunchAfterInstall {
		t.Fatal("expected default shortcuts and startup enabled")
	}
	if opts.Silent {
		t.Fatal("expected default silent to be false")
	}
}

func TestDefaultInstallDir(t *testing.T) {
	dir := installer.DefaultInstallDir()
	if dir == "" {
		t.Fatal("expected non-empty default install dir")
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("expected absolute path, got %s", dir)
	}
}

func createFakeExe(size int) []byte {
	buf := make([]byte, size)
	buf[0] = 'M'
	buf[1] = 'Z'
	return buf
}

func TestExtractPayloadFromDirectory(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	netscanData := createFakeExe(1024 * 600)
	updaterData := createFakeExe(1024 * 600)

	if err := os.WriteFile(filepath.Join(srcDir, "netscan.exe"), netscanData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "updater.exe"), updaterData, 0755); err != nil {
		t.Fatal(err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(srcDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	var progressCalled bool
	err = installer.ExtractPayload(destDir, func(pct int, msg string) {
		progressCalled = true
	})
	if err != nil {
		t.Fatalf("ExtractPayload failed: %v", err)
	}

	if !progressCalled {
		t.Fatal("expected progress callback")
	}

	if _, err := os.Stat(filepath.Join(destDir, "netscan.exe")); err != nil {
		t.Fatal("expected netscan.exe in destDir")
	}
	if _, err := os.Stat(filepath.Join(destDir, "updater.exe")); err != nil {
		t.Fatal("expected updater.exe in destDir")
	}
}

// The release installer is installer.exe with the payload zip appended
// (copy /b installer-base.exe+netscan-windows-amd64.zip). This builds the
// same layout in a temp file, so the test doesn't depend on a local dist/
// build, and checks the payload can be read back.
func TestOpenAppendedInstallerZip(t *testing.T) {
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for _, name := range []string{"netscan.exe", "updater.exe"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(createFakeExe(4096)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "netscan-installer.exe")
	combined := append(createFakeExe(64*1024), zipBuf.Bytes()...)
	if err := os.WriteFile(path, combined, 0755); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("zip.OpenReader on appended installer failed: %v", err)
	}
	defer zr.Close()
	found := map[string]bool{}
	for _, f := range zr.File {
		found[f.Name] = true
	}
	if !found["netscan.exe"] || !found["updater.exe"] {
		t.Fatalf("payload entries missing, got %v", found)
	}
}

func TestInstall(t *testing.T) {
	// Run from a directory holding the payload, the same fallback the
	// installer uses when it has no embedded zip.
	srcDir := t.TempDir()
	for _, name := range []string{"netscan.exe", "updater.exe"} {
		if err := os.WriteFile(filepath.Join(srcDir, name), createFakeExe(1024*600), 0755); err != nil {
			t.Fatal(err)
		}
	}
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(srcDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	destDir := filepath.Join(t.TempDir(), "target")
	opts := installer.Options{
		InstallDir:         destDir,
		DesktopShortcut:    false,
		StartMenuShortcut:  false,
		RunAtStartup:       false,
		LaunchAfterInstall: false,
		Silent:             true,
	}
	if err := installer.Install(opts, "0.2.0", nil); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "netscan.exe")); err != nil {
		t.Fatal("expected netscan.exe installed in destDir")
	}
}
