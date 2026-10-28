<p align="center"><img src="assets/logo.svg" width="96" alt="NetScan logo"></p>

# NetScan

A lightweight internet stability monitor for Windows and Linux (amd64 and arm64, including the Raspberry Pi) designed to detect micro-drops, isolate connection faults, and log historical network health.

## Features

- **Micro-Drop Detection**: High-frequency probing to catch outages lasting under 10 seconds.
- **Fault Domain Isolation**: Identifies failures at Gateway, WAN, DNS, or HTTP levels.
- **System Tray Integration**: Background monitoring with dynamic status icon.
- **Web Dashboard**: Built-in UI for inspecting latency, outages, and event timelines.
- **Telemetry & Exports**: SQLite-backed history with exportable reports.
- **Self-Updating**: Direct GitHub release checking, background notifications, and one-click in-place updates.

## Build

The app icon lives in `assets/logo.svg`. The Windows resource files (`cmd/*/rsrc_windows_amd64.syso`) embed `assets/logo.ico` and are picked up automatically by `go build`. To regenerate after changing the logo: `rsrc -ico assets/logo.ico -arch amd64 -o cmd/netscan/rsrc_windows_amd64.syso` (and copy to `cmd/installer/`).

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

NetScan runs on Windows and Linux. OS-specific code lives in `internal/platform` behind build tags, and the core packages (probes, scheduler, detector, store, server) build and test on any OS.

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

## Linux

Linux builds are headless: there is no tray icon, and the dashboard is served on the loopback address only ([http://127.0.0.1:9095](http://127.0.0.1:9095)). Download the tarball for your CPU from the [latest release](https://github.com/aaronburt/netscan/releases/latest) (`netscan-linux-amd64.tar.gz`, or `netscan-linux-arm64.tar.gz` for a Raspberry Pi 4 or other 64-bit ARM board), then install it as a systemd service:

```sh
tar -xzf netscan-linux-arm64.tar.gz
cd netscan-linux-arm64
sudo ./install.sh
```

The script creates a `netscan` system user, installs the binary to `/opt/netscan/netscan` (linked from `/usr/local/bin/netscan`) and the unit to `/etc/systemd/system/netscan.service`, then enables and starts the service. History and config live in `/var/lib/netscan`. Running `install.sh` again from a newer tarball upgrades in place.

```sh
systemctl status netscan
journalctl -u netscan -f
```

The service user owns `/opt/netscan`, so the dashboard's **Download & Install** button can update NetScan itself: it verifies the release checksum, swaps the binary, and exits so systemd (`Restart=always`) starts the new version. If the binary's directory isn't writable (for example a binary you placed in `/usr/local/bin` yourself), the dashboard points you to the release page instead. To update from a shell, run `sudo systemctl restart netscan` after `netscan -update`, or re-run `install.sh` from the new tarball.

To remove it, run `sudo ./uninstall.sh` from the extracted tarball. Your history is kept in `/var/lib/netscan`; add `--purge` to delete it and the `netscan` user too.

## Docker

NetScan also ships as a container image for amd64 and arm64, including a Raspberry Pi 4 or other 64-bit ARM board. The image runs headless as a nonroot user on a distroless base. Run Compose on the host you want to monitor:

```sh
docker compose up -d --build                  # build from this checkout
docker compose pull && docker compose up -d   # or run the published image
```

Published images are at `ghcr.io/aaronburt/netscan`, with a version tag and `latest` on every release.

- **Network:** the Compose file uses host networking, so NetScan sees the host's default gateway, ARP table and interfaces. The gateway checks depend on that. On a bridge network it would see Docker's own gateway instead.
- **Dashboard:** it listens on `127.0.0.1:9095` on the host. From another machine, open an SSH tunnel with `ssh -L 9095:127.0.0.1:9095 <host>` and browse to http://127.0.0.1:9095 there. The dashboard has no login, so it stays on loopback.
- **Updates:** the Updates button is hidden in a container, because the image is the update. Run `docker compose pull && docker compose up -d` to move to a new release.
- **Data:** history and config live in the `netscan-data` volume. To keep them in a host folder, bind-mount it and make it writable by UID 65532: `sudo chown -R 65532:65532 ./data`.
- **Pings:** gateway and WAN ping checks need unprivileged ping sockets, since the container has no raw-socket rights. Check the host with `sysctl net.ipv4.ping_group_range`. If the range does not include 65532, allow it:

  ```sh
  echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/99-netscan.conf
  sudo sysctl --system
  ```

  Without that, NetScan logs a warning and leaves the gateway and WAN ping layers unknown. Outage detection still uses TCP, DNS and HTTP.

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

### Turning the Dashboard Off

Right-click the tray icon and untick **Enable WebUI** to stop serving the dashboard. It takes effect immediately, is remembered across restarts (`"http": {"enabled": false}` in `config.json`), and probing and recording carry on as before. The dashboard-related tray items are greyed out while it is off.

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

Every merged PR ships a release automatically. The PR title decides the version bump, using [Conventional Commit](https://www.conventionalcommits.org/) types:

- `feat: ...` bumps the minor version (0.5.0 → 0.6.0)
- anything else (`fix:`, `perf:`, `refactor:`, `docs:`, `test:`, `build:`, `ci:`, `chore:`, `style:`, `revert:`) bumps the patch version (0.5.0 → 0.5.1)
- `!` breaking-change markers in a title are rejected: major bumps are never automatic

A `PR title` check enforces the format. On merge, the `Release` workflow tests and builds the Windows binaries, then creates the tag and GitHub Release with `netscan-windows-amd64.zip`, `netscan-installer.exe`, `netscan.exe`, `updater.exe`, `netscan-linux-amd64.tar.gz`, `netscan-linux-arm64.tar.gz` and `checksums.txt`. After the release exists, the same workflow pushes the container image to `ghcr.io/aaronburt/netscan` for amd64 and arm64, tagged with the version and `latest`.

### Major release

Go to **Actions → Release → Run workflow**, pick `main`, and set `bump` to `major` (0.5.0 → 1.0.0).

### Rebuilding a release

If a release run fails, run the same workflow with `rebuild_tag` set to the tag (e.g. `v0.5.1`) to rebuild and re-upload its assets.
