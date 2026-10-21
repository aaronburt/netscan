package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ReleaseAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"browser_download_url"`
}

type Release struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	HTMLURL     string         `json:"html_url"`
	PublishedAt time.Time      `json:"published_at"`
	Draft       bool           `json:"draft"`
	Prerelease  bool           `json:"prerelease"`
	Assets      []ReleaseAsset `json:"assets"`
	Version      string         `json:"version"`
	AssetURL     string         `json:"asset_url"`
	AssetName    string         `json:"asset_name"`
	AssetSize    int64          `json:"asset_size"`
	ChecksumURL  string         `json:"checksum_url,omitempty"`
	ExpectedHash string         `json:"expected_hash,omitempty"`
}

type CheckResult struct {
	CurrentVersion  string   `json:"current_version"`
	LatestVersion   string   `json:"latest_version"`
	UpdateAvailable bool     `json:"update_available"`
	Release         *Release `json:"release,omitempty"`
}

var ErrNoReleases = errors.New("no releases found")

func CleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func parseVersion(v string) ([]int, string) {
	v = CleanVersion(v)
	pre := ""
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		pre = v[idx+1:]
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums, pre
}

func CompareVersions(v1, v2 string) int {
	nums1, pre1 := parseVersion(v1)
	nums2, pre2 := parseVersion(v2)

	for i := 0; i < 3; i++ {
		if nums1[i] < nums2[i] {
			return -1
		}
		if nums1[i] > nums2[i] {
			return 1
		}
	}

	if pre1 == "" && pre2 != "" {
		return 1
	}
	if pre1 != "" && pre2 == "" {
		return -1
	}
	if pre1 != "" && pre2 != "" {
		return strings.Compare(pre1, pre2)
	}

	return 0
}

func SelectAsset(assets []ReleaseAsset, targetOS, targetArch string) (ReleaseAsset, bool) {
	if len(assets) == 0 {
		return ReleaseAsset{}, false
	}

	if targetOS == "" {
		targetOS = runtime.GOOS
	}
	if targetArch == "" {
		targetArch = runtime.GOARCH
	}

	var best ReleaseAsset
	bestScore := -1

	for _, a := range assets {
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, "updater") {
			continue
		}
		score := 0

		isZip := strings.HasSuffix(lower, ".zip")
		isExe := strings.HasSuffix(lower, ".exe")

		if !isZip && !isExe {
			continue
		}

		if targetOS == "windows" {
			if strings.Contains(lower, "windows") || strings.Contains(lower, "win") {
				score += 20
			}
		}

		if targetArch == "amd64" {
			if strings.Contains(lower, "amd64") || strings.Contains(lower, "x86_64") || strings.Contains(lower, "x64") {
				score += 20
			}
		} else if targetArch == "arm64" {
			if strings.Contains(lower, "arm64") {
				score += 20
			}
		}

		if strings.HasPrefix(lower, "netscan") {
			score += 10
		}

		if isZip {
			score += 5
		} else if isExe {
			score += 4
		}

		if score > bestScore {
			bestScore = score
			best = a
		}
	}

	if bestScore >= 0 {
		return best, true
	}

	return ReleaseAsset{}, false
}

func FindChecksumAsset(assets []ReleaseAsset, targetAssetName string) (ReleaseAsset, bool) {
	for _, a := range assets {
		lower := strings.ToLower(a.Name)
		if lower == "checksums.txt" || lower == "sha256sums" || lower == "sha256sums.txt" || lower == "checksums.sha256" {
			return a, true
		}
		if lower == strings.ToLower(targetAssetName)+".sha256" {
			return a, true
		}
	}
	return ReleaseAsset{}, false
}

func ParseExpectedChecksum(content string, targetAssetName string) string {
	lines := strings.Split(content, "\n")
	cleanTarget := strings.ToLower(filepath.Base(targetAssetName))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 1 && len(fields[0]) == 64 {
			return strings.ToLower(fields[0])
		}

		if len(fields) >= 2 {
			hash := fields[0]
			file := strings.TrimPrefix(fields[1], "*")
			file = strings.ToLower(filepath.Base(file))
			if len(hash) == 64 && (file == cleanTarget || cleanTarget == "") {
				return strings.ToLower(hash)
			}
		}
	}
	return ""
}

func FetchChecksumContent(ctx context.Context, client *http.Client, url string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NetScan-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching checksums failed with status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func FetchLatestRelease(ctx context.Context, client *http.Client, repo string) (*Release, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	url := repo
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "NetScan-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoReleases
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to decode release response: %w", err)
	}

	rel.Version = CleanVersion(rel.TagName)
	if best, ok := SelectAsset(rel.Assets, runtime.GOOS, runtime.GOARCH); ok {
		rel.AssetURL = best.DownloadURL
		rel.AssetName = best.Name
		rel.AssetSize = best.Size

		if csAsset, csOk := FindChecksumAsset(rel.Assets, best.Name); csOk {
			rel.ChecksumURL = csAsset.DownloadURL
			if csContent, err := FetchChecksumContent(ctx, client, csAsset.DownloadURL); err == nil {
				rel.ExpectedHash = ParseExpectedChecksum(csContent, best.Name)
			}
		}
	}

	return &rel, nil
}

func CheckForUpdate(ctx context.Context, client *http.Client, repo string, currentVersion string) (*CheckResult, error) {
	rel, err := FetchLatestRelease(ctx, client, repo)
	if err != nil {
		if errors.Is(err, ErrNoReleases) {
			return &CheckResult{
				CurrentVersion:  currentVersion,
				LatestVersion:   CleanVersion(currentVersion),
				UpdateAvailable: false,
			}, nil
		}
		return nil, err
	}

	cleanCurrent := CleanVersion(currentVersion)
	cmp := CompareVersions(cleanCurrent, rel.Version)
	updateAvailable := cmp < 0

	if strings.Contains(strings.ToLower(currentVersion), "dev") {
		updateAvailable = true
	}

	return &CheckResult{
		CurrentVersion:  currentVersion,
		LatestVersion:   rel.Version,
		UpdateAvailable: updateAvailable,
		Release:         rel,
	}, nil
}

type progressTrackingWriter struct {
	total      int64
	downloaded int64
	callback   func(downloaded, total int64)
}

func (ptw *progressTrackingWriter) Write(p []byte) (int, error) {
	n := len(p)
	ptw.downloaded += int64(n)
	if ptw.callback != nil {
		ptw.callback(ptw.downloaded, ptw.total)
	}
	return n, nil
}

func DownloadAndExtract(ctx context.Context, client *http.Client, assetURL string, targetDir string, expectedHash string, progressFn func(downloaded, total int64)) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "NetScan-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp(targetDir, "netscan-download-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpFilePath := tmpFile.Name()

	pw := &progressTrackingWriter{
		total:    resp.ContentLength,
		callback: progressFn,
	}

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, pw, hasher)
	_, copyErr := io.Copy(writer, resp.Body)
	_ = tmpFile.Close()

	if copyErr != nil {
		_ = os.Remove(tmpFilePath)
		return "", fmt.Errorf("failed to write download file: %w", copyErr)
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && !strings.EqualFold(computedHash, expectedHash) {
		_ = os.Remove(tmpFilePath)
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, computedHash)
	}

	zipReader, zipErr := zip.OpenReader(tmpFilePath)
	if zipErr == nil {
		defer zipReader.Close()
		defer os.Remove(tmpFilePath)

		var targetZipFile *zip.File
		var updaterZipFile *zip.File
		for _, f := range zipReader.File {
			base := strings.ToLower(filepath.Base(f.Name))
			if base == "updater.exe" {
				updaterZipFile = f
				continue
			}
			if base == "netscan.exe" {
				targetZipFile = f
				continue
			}
			if strings.HasSuffix(base, ".exe") && targetZipFile == nil {
				targetZipFile = f
			}
		}

		if updaterZipFile != nil {
			if urc, uerr := updaterZipFile.Open(); uerr == nil {
				if utmp, terr := os.CreateTemp(targetDir, "updater-extracted-*.tmp"); terr == nil {
					utmpPath := utmp.Name()
					_, ucopyErr := io.Copy(utmp, urc)
					_ = utmp.Close()
					if ucopyErr == nil {
						updaterDest := filepath.Join(targetDir, "updater.exe")
						if err := os.Rename(utmpPath, updaterDest); err != nil {
							_ = os.Remove(utmpPath)
						}
					} else {
						_ = os.Remove(utmpPath)
					}
				}
				_ = urc.Close()
			}
		}

		if targetZipFile == nil {
			return "", errors.New("no executable found in downloaded zip archive")
		}

		rc, err := targetZipFile.Open()
		if err != nil {
			return "", fmt.Errorf("failed to read zip member: %w", err)
		}
		defer rc.Close()

		extractedFile, err := os.CreateTemp(targetDir, "netscan-extracted-*.tmp")
		if err != nil {
			return "", fmt.Errorf("failed to create extracted executable file: %w", err)
		}
		extractedPath := extractedFile.Name()

		_, copyErr = io.Copy(extractedFile, rc)
		_ = extractedFile.Close()

		if copyErr != nil {
			_ = os.Remove(extractedPath)
			return "", fmt.Errorf("failed to extract executable from zip: %w", copyErr)
		}

		return extractedPath, nil
	}

	return tmpFilePath, nil
}

func ValidateExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() < 512*1024 {
		return errors.New("downloaded file is too small to be a valid executable")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(f, header); err != nil {
		return err
	}
	if !bytes.Equal(header, []byte("MZ")) {
		return errors.New("downloaded file does not contain valid executable signature")
	}
	return nil
}

func ExecutablePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	exePath = strings.TrimSuffix(exePath, ".old")
	return exePath, nil
}

func ReplaceCurrentBinary(newBinaryPath string) error {
	exePath, err := ExecutablePath()
	if err != nil {
		return err
	}

	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)

	if err := os.Rename(exePath, oldPath); err != nil {
		return fmt.Errorf("failed to rename current binary: %w", err)
	}

	if err := os.Rename(newBinaryPath, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		return fmt.Errorf("failed to move new binary into place: %w", err)
	}

	return nil
}

func RelaunchExecutable(args []string) error {
	exePath, err := ExecutablePath()
	if err != nil {
		return err
	}

	filteredArgs := make([]string, 0, len(args))
	for _, arg := range args {
		trimmed := strings.TrimLeft(strings.ToLower(arg), "-")
		if trimmed == "update" || trimmed == "check-update" || strings.HasPrefix(trimmed, "update=") || strings.HasPrefix(trimmed, "check-update=") {
			continue
		}
		filteredArgs = append(filteredArgs, arg)
	}

	cmd := exec.Command(exePath, filteredArgs...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := StartDetachedProcess(cmd); err != nil {
		return fmt.Errorf("failed to start updated application: %w", err)
	}
	return nil
}

func UpdaterBinaryPath(targetDir string) string {
	return filepath.Join(targetDir, "updater.exe")
}

func HasUpdaterBinary(targetDir string) bool {
	fi, err := os.Stat(UpdaterBinaryPath(targetDir))
	return err == nil && !fi.IsDir()
}

func LaunchUpdaterHelper(updaterPath, targetExePath, stagedExePath string, pid int, forwardArgs []string) error {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-target", targetExePath,
	}
	if stagedExePath != "" {
		args = append(args, "-source", stagedExePath)
	}
	for _, a := range forwardArgs {
		trimmed := strings.TrimLeft(strings.ToLower(a), "-")
		if trimmed == "update" || trimmed == "check-update" || strings.HasPrefix(trimmed, "update=") || strings.HasPrefix(trimmed, "check-update=") {
			continue
		}
		args = append(args, "-arg", a)
	}

	cmd := exec.Command(updaterPath, args...)
	cmd.Dir = filepath.Dir(targetExePath)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := StartDetachedProcess(cmd); err != nil {
		return fmt.Errorf("failed to start updater helper: %w", err)
	}
	return nil
}

func CleanupOldBinary() {
	exePath, err := ExecutablePath()
	if err != nil {
		return
	}
	oldPath := exePath + ".old"
	if _, err := os.Stat(oldPath); err != nil {
		return
	}
	if err := os.Remove(oldPath); err == nil {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if err := os.Remove(oldPath); err == nil || os.IsNotExist(err) {
				return
			}
		}
	}()
}
