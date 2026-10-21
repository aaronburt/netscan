//go:build windows

package installer_test

import (
	"archive/zip"
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

func TestOpenDistInstallerZip(t *testing.T) {
	zr, err := zip.OpenReader("../../dist/netscan-installer.exe")
	if err != nil {
		t.Fatalf("zip.OpenReader on dist/netscan-installer.exe failed: %v", err)
	}
	defer zr.Close()
	t.Logf("found %d entries in dist/netscan-installer.exe", len(zr.File))
	for _, f := range zr.File {
		t.Logf("entry: %s (size: %d)", f.Name, f.UncompressedSize64)
	}
}

func TestInstall(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
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
