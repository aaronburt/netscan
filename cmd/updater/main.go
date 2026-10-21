package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/updater"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, " ")
}

func (m *multiStringFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

var version = "0.4.0"

func main() {
	versionFlag := flag.Bool("version", false, "print version")
	pidFlag := flag.Int("pid", 0, "process id to wait for before replacing binary")
	targetFlag := flag.String("target", "", "path to target executable")
	sourceFlag := flag.String("source", "", "path to staged binary to install")
	repoFlag := flag.String("repo", "aaronburt/netscan", "github repository for release updates")
	noRelaunchFlag := flag.Bool("no-relaunch", false, "do not relaunch target binary after update")

	var forwardArgs multiStringFlag
	flag.Var(&forwardArgs, "arg", "argument to forward to relaunched binary")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("netscan-updater %s\n", version)
		return
	}

	targetPath := *targetFlag
	if targetPath == "" {
		selfExe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "updater: failed to determine executable path: %v\n", err)
			os.Exit(1)
		}
		selfExe, _ = filepath.EvalSymlinks(selfExe)
		targetPath = filepath.Join(filepath.Dir(selfExe), "netscan.exe")
	}

	targetDir := filepath.Dir(targetPath)
	sourcePath := *sourceFlag

	if sourcePath == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		fmt.Printf("Checking GitHub (%s) for latest release...\n", *repoFlag)
		rel, err := updater.FetchLatestRelease(ctx, nil, *repoFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "updater: failed to fetch release: %v\n", err)
			os.Exit(1)
		}
		if rel.AssetURL == "" {
			fmt.Fprintln(os.Stderr, "updater: no compatible release asset found")
			os.Exit(1)
		}

		fmt.Printf("Downloading %s (%s)...\n", rel.Version, rel.AssetName)
		downloadedPath, err := updater.DownloadAndExtract(ctx, nil, rel.AssetURL, targetDir, rel.ExpectedHash, func(down, tot int64) {
			if tot > 0 {
				pct := float64(down) / float64(tot) * 100
				fmt.Printf("\rProgress: %.1f%% (%d / %d bytes)", pct, down, tot)
			}
		})
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "updater: download failed: %v\n", err)
			os.Exit(1)
		}

		sourcePath = downloadedPath
	}

	if err := updater.ValidateExecutable(sourcePath); err != nil {
		_ = os.Remove(sourcePath)
		fmt.Fprintf(os.Stderr, "updater: binary validation failed: %v\n", err)
		os.Exit(1)
	}

	if *pidFlag > 0 {
		updater.WaitForPIDExit(*pidFlag, 6*time.Second)
	}

	updater.StopRunningProcessByName(filepath.Base(targetPath), 4*time.Second)

	if err := updater.InstallBinaryWithRetry(sourcePath, targetPath); err != nil {
		_ = os.Remove(sourcePath)
		fmt.Fprintf(os.Stderr, "updater: failed to replace binary: %v\n", err)
		os.Exit(1)
	}

	_ = os.Remove(sourcePath)
	fmt.Printf("Successfully updated %s\n", filepath.Base(targetPath))

	if !*noRelaunchFlag {
		cmd := exec.Command(targetPath, forwardArgs...)
		cmd.Dir = targetDir
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := updater.StartDetachedProcess(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "updater: failed to relaunch %s: %v\n", targetPath, err)
			os.Exit(1)
		}
	}
}
