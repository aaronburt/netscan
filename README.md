# NetScan

A lightweight Windows internet stability monitor designed to detect micro-drops, isolate connection faults, and log historical network health.

## Features

- **Micro-Drop Detection**: High-frequency probing to catch outages lasting under 10 seconds.
- **Fault Domain Isolation**: Identifies failures at Gateway, WAN, DNS, or HTTP levels.
- **System Tray Integration**: Background monitoring with dynamic status icon.
- **Web Dashboard**: Built-in UI for inspecting latency, outages, and event timelines.
- **Telemetry & Exports**: SQLite-backed history with exportable reports.
- **Self-Updating**: Direct GitHub release checking, background notifications, and one-click in-place updates.

## Build

```powershell
go build -ldflags "-H=windowsgui" -o dist\netscan.exe ./cmd/netscan
go build -ldflags "-s -w" -o dist\updater.exe ./cmd/updater
go build -ldflags "-s -w -H=windowsgui" -o dist\installer-base.exe ./cmd/installer
Compress-Archive -Path dist\netscan.exe, dist\updater.exe -DestinationPath dist\netscan-windows-amd64.zip -Force
cmd /c copy /b dist\installer-base.exe+dist\netscan-windows-amd64.zip dist\netscan-installer.exe
Remove-Item dist\installer-base.exe
```

## Installation

Run the self-contained installer:

```powershell
.\dist\netscan-installer.exe
```

Or install silently:

```powershell
.\dist\netscan-installer.exe -silent
```

To uninstall:

```powershell
.\dist\netscan-installer.exe -uninstall
```

Or use Windows Settings -> Installed Apps -> NetScan -> Uninstall.

## Usage

### Standard Mode (System Tray)

```powershell
.\dist\netscan.exe
```

Open the dashboard in your browser:
[http://127.0.0.1:9095](http://127.0.0.1:9095)

### Headless Mode (Console)

```powershell
.\dist\netscan.exe -headless
```

### Custom Configuration

```powershell
.\dist\netscan.exe -config path\to\config.json
```

### Checking & Installing Updates

Check GitHub for available releases:

```powershell
.\dist\netscan.exe -check-update
```

Download and apply latest update directly:

```powershell
.\dist\netscan.exe -update
```

Or run the standalone updater helper in the `dist\` folder (pulls latest release, stops `netscan.exe`, replaces the binary, and relaunches it):

```powershell
.\dist\updater.exe
```
