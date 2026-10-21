package installer

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/updater"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Options struct {
	InstallDir         string
	DesktopShortcut    bool
	StartMenuShortcut  bool
	RunAtStartup       bool
	LaunchAfterInstall bool
	Silent             bool
}

func DefaultOptions() Options {
	return Options{
		InstallDir:         DefaultInstallDir(),
		DesktopShortcut:    true,
		StartMenuShortcut:  true,
		RunAtStartup:       true,
		LaunchAfterInstall: true,
		Silent:             false,
	}
}

func DefaultInstallDir() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return `C:\NetScan`
		}
		return filepath.Join(home, "AppData", "Local", "Programs", "NetScan")
	}
	return filepath.Join(localAppData, "Programs", "NetScan")
}

func ExtractPayload(targetDir string, onProgress func(pct int, msg string)) error {
	exePath, err := os.Executable()
	if err == nil {
		zr, err := zip.OpenReader(exePath)
		if err == nil {
			defer zr.Close()
			extractedAny := false
			total := len(zr.File)
			for i, f := range zr.File {
				base := filepath.Base(f.Name)
				if base != "netscan.exe" && base != "updater.exe" {
					continue
				}
				destPath := filepath.Join(targetDir, base)
				if err := extractZipFile(f, destPath); err != nil {
					return err
				}
				extractedAny = true
				if onProgress != nil {
					pct := 25 + int(float64(i+1)/float64(total)*30)
					onProgress(pct, "Extracting "+base)
				}
			}
			if extractedAny && hasFile(filepath.Join(targetDir, "netscan.exe")) {
				_ = copySelfAsUninstaller(exePath, targetDir)
				return nil
			}
		}
	}

	candidates := []string{
		filepath.Dir(exePath),
		filepath.Join(filepath.Dir(exePath), "dist"),
		".",
		"dist",
	}

	foundNetscan := false
	for _, dir := range candidates {
		netscanSrc := filepath.Join(dir, "netscan.exe")
		if hasFile(netscanSrc) {
			if onProgress != nil {
				onProgress(30, "Copying netscan.exe")
			}
			if err := copyFile(netscanSrc, filepath.Join(targetDir, "netscan.exe")); err != nil {
				return err
			}
			foundNetscan = true

			updaterSrc := filepath.Join(dir, "updater.exe")
			if hasFile(updaterSrc) {
				if onProgress != nil {
					onProgress(45, "Copying updater.exe")
				}
				_ = copyFile(updaterSrc, filepath.Join(targetDir, "updater.exe"))
			}
			break
		}
	}

	if !foundNetscan {
		return errors.New("installation payload (netscan.exe) could not be located")
	}

	_ = copySelfAsUninstaller(exePath, targetDir)
	return nil
}

func extractZipFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	tmpPath := destPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(out, rc)
	_ = out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}

	return updater.InstallBinaryWithRetry(tmpPath, destPath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpDst := dst + ".tmp"
	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(out, in)
	_ = out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpDst)
		return copyErr
	}

	return updater.InstallBinaryWithRetry(tmpDst, dst)
}

func copySelfAsUninstaller(exePath, targetDir string) error {
	if exePath == "" {
		return nil
	}
	dst := filepath.Join(targetDir, "uninstall.exe")
	if strings.EqualFold(filepath.Clean(exePath), filepath.Clean(dst)) {
		return nil
	}
	return copyFile(exePath, dst)
}

func hasFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func CreateDesktopShortcut(targetExe string) error {
	desktopDir := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	lnkPath := filepath.Join(desktopDir, "NetScan.lnk")
	return createShortcut(targetExe, lnkPath, "NetScan Network Stability Monitor")
}

func CreateStartMenuShortcut(targetExe string) error {
	appData := os.Getenv("APPDATA")
	programsDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
	_ = os.MkdirAll(programsDir, 0755)
	lnkPath := filepath.Join(programsDir, "NetScan.lnk")
	return createShortcut(targetExe, lnkPath, "NetScan Network Stability Monitor")
}

func RemoveDesktopShortcut() error {
	desktopDir := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	lnkPath := filepath.Join(desktopDir, "NetScan.lnk")
	if err := os.Remove(lnkPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func RemoveStartMenuShortcut() error {
	appData := os.Getenv("APPDATA")
	programsDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
	lnkPath := filepath.Join(programsDir, "NetScan.lnk")
	if err := os.Remove(lnkPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func createShortcut(targetExe, lnkPath, description string) error {
	safeLnk := strings.ReplaceAll(lnkPath, "'", "''")
	safeExe := strings.ReplaceAll(targetExe, "'", "''")
	safeDir := strings.ReplaceAll(filepath.Dir(targetExe), "'", "''")
	safeDesc := strings.ReplaceAll(description, "'", "''")

	script := fmt.Sprintf(
		"$ws=New-Object -ComObject WScript.Shell;$s=$ws.CreateShortcut('%s');$s.TargetPath='%s';$s.WorkingDirectory='%s';$s.Description='%s';$s.Save()",
		safeLnk,
		safeExe,
		safeDir,
		safeDesc,
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd.Run()
}

func SetAutostart(targetExe string, enabled bool) error {
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		return err
	}
	defer key.Close()

	if !enabled {
		err := key.DeleteValue("NetScan")
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	quoted := fmt.Sprintf("\"%s\"", filepath.Clean(targetExe))
	return key.SetStringValue("NetScan", quoted)
}

func RegisterUninstall(targetDir, version string) error {
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Uninstall\NetScan`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer key.Close()

	targetExe := filepath.Join(targetDir, "netscan.exe")
	uninstallExe := filepath.Join(targetDir, "uninstall.exe")

	_ = key.SetStringValue("DisplayName", "NetScan")
	if version != "" {
		_ = key.SetStringValue("DisplayVersion", strings.TrimPrefix(version, "v"))
	}
	_ = key.SetStringValue("Publisher", "Aaron Burt")
	_ = key.SetStringValue("InstallLocation", targetDir)
	_ = key.SetStringValue("UninstallString", fmt.Sprintf("\"%s\" -uninstall", uninstallExe))
	_ = key.SetStringValue("QuietUninstallString", fmt.Sprintf("\"%s\" -uninstall -silent", uninstallExe))
	_ = key.SetStringValue("DisplayIcon", fmt.Sprintf("%s,0", targetExe))
	_ = key.SetDWordValue("NoModify", 1)
	_ = key.SetDWordValue("NoRepair", 1)
	return nil
}

func UnregisterUninstall() error {
	err := registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall\NetScan`)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func LaunchBinary(exePath string) error {
	cmd := exec.Command(exePath)
	cmd.Dir = filepath.Dir(exePath)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}

func Install(opts Options, version string, onProgress func(pct int, msg string)) error {
	if onProgress != nil {
		onProgress(5, "Stopping existing processes...")
	}
	updater.StopRunningProcessByName("netscan.exe", 3*time.Second)
	updater.StopRunningProcessByName("updater.exe", 3*time.Second)
	time.Sleep(200 * time.Millisecond)

	if onProgress != nil {
		onProgress(15, "Preparing directory...")
	}
	if err := os.MkdirAll(opts.InstallDir, 0755); err != nil {
		return err
	}

	if onProgress != nil {
		onProgress(25, "Extracting binaries...")
	}
	if err := ExtractPayload(opts.InstallDir, onProgress); err != nil {
		return err
	}

	netscanExe := filepath.Join(opts.InstallDir, "netscan.exe")

	if opts.DesktopShortcut {
		if onProgress != nil {
			onProgress(65, "Creating Desktop shortcut...")
		}
		_ = CreateDesktopShortcut(netscanExe)
	}

	if opts.StartMenuShortcut {
		if onProgress != nil {
			onProgress(75, "Creating Start Menu shortcut...")
		}
		_ = CreateStartMenuShortcut(netscanExe)
	}

	if opts.RunAtStartup {
		if onProgress != nil {
			onProgress(85, "Configuring autostart...")
		}
		_ = SetAutostart(netscanExe, true)
	}

	if onProgress != nil {
		onProgress(92, "Registering in Windows...")
	}
	_ = RegisterUninstall(opts.InstallDir, version)

	if opts.LaunchAfterInstall {
		if onProgress != nil {
			onProgress(98, "Launching NetScan...")
		}
		_ = LaunchBinary(netscanExe)
	}

	if onProgress != nil {
		onProgress(100, "Installation complete.")
	}
	return nil
}

func Uninstall() error {
	updater.StopRunningProcessByName("netscan.exe", 3*time.Second)
	updater.StopRunningProcessByName("updater.exe", 3*time.Second)
	time.Sleep(200 * time.Millisecond)

	_ = RemoveDesktopShortcut()
	_ = RemoveStartMenuShortcut()
	_ = SetAutostart("", false)
	_ = UnregisterUninstall()

	exePath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exePath)
		_ = scheduleDirectoryCleanup(dir)
	}
	return nil
}

func scheduleDirectoryCleanup(dir string) error {
	script := fmt.Sprintf("cmd.exe /c timeout /t 1 /nobreak >nul & rmdir /s /q \"%s\"", dir)
	cmd := exec.Command("cmd.exe", "/c", script)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}
