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

## How often it probes

In normal mode NetScan makes about 3 probes a second:

| Probe | Normal mode |
|---|---|
| Gateway ping | every second |
| First WAN ping host (1.1.1.1) | every second |
| Other WAN ping hosts | one every 5 s, alternating |
| ISP hop ping | every 2 s |
| WAN TCP, DNS | one target every 5 s, rotating |
| HTTP | one target every 15 s, rotating |

A failed probe is confirmed straight away against another target in the same layer, and anything suspicious switches to fast mode, which probes every target every 0.5 s until things settle. Those rates are the `intervals` section of `config.json` (`isp_hop_ms`, `wan_icmp_secondary_ms`, `wan_tcp_ms`, `dns_ms`, `http_ms`). Set them all to `normal_ms` to probe every layer every tick.

## Development

NetScan only runs on Windows, but the core packages (probes, scheduler, detector, store, server) build and test on any OS. Windows-only code sits behind build tags with small stubs for other platforms.

```sh
go vet ./...
go test -race ./...
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

## Releases

Releases are automated with [release-please](https://github.com/googleapis/release-please). Use [Conventional Commits](https://www.conventionalcommits.org/) on `main`:

- `fix: ...` bumps the patch version (0.4.2 → 0.4.3)
- `feat: ...` bumps the minor version (0.4.2 → 0.5.0)
- `feat!: ...` or a `BREAKING CHANGE:` footer marks a breaking change (bumps minor while below 1.0)
- `chore:`, `docs:`, `ci:`, `refactor:`, `test:` don't trigger a release

On each push to `main`, a release PR is kept up to date with the next version and changelog. Merging it tags the release, creates the GitHub Release, and uploads the Windows build (`netscan-windows-amd64.zip`, `netscan-installer.exe`, `netscan.exe`, `updater.exe`, `checksums.txt`).
