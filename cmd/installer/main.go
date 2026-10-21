package main

import (
	"flag"
	"os"
	"strings"

	"github.com/aaronburt/netscan/internal/installer"
)

var version = "0.4.2" // x-release-please-version

func main() {
	dirFlag := flag.String("dir", "", "installation directory")
	silentFlag := flag.Bool("silent", false, "silent unattended installation")
	noDesktopFlag := flag.Bool("no-desktop", false, "do not create desktop shortcut")
	noStartMenuFlag := flag.Bool("no-startmenu", false, "do not create start menu shortcut")
	noStartupFlag := flag.Bool("no-startup", false, "do not register in windows startup")
	noLaunchFlag := flag.Bool("no-launch", false, "do not launch netscan after installation")
	uninstallFlag := flag.Bool("uninstall", false, "uninstall netscan")
	flag.Parse()

	silent := *silentFlag
	for _, arg := range os.Args[1:] {
		if strings.EqualFold(arg, "/s") || strings.EqualFold(arg, "/silent") {
			silent = true
			break
		}
	}

	if *uninstallFlag {
		_ = runUninstallPrompt(silent)
		return
	}

	opts := installer.DefaultOptions()
	if *dirFlag != "" {
		opts.InstallDir = *dirFlag
	}
	if *noDesktopFlag {
		opts.DesktopShortcut = false
	}
	if *noStartMenuFlag {
		opts.StartMenuShortcut = false
	}
	if *noStartupFlag {
		opts.RunAtStartup = false
	}
	if *noLaunchFlag {
		opts.LaunchAfterInstall = false
	}
	opts.Silent = silent

	if opts.Silent {
		if err := installer.Install(opts, version, nil); err != nil {
			os.Exit(1)
		}
		return
	}

	_ = runInstallerGUI(version, opts)
}
