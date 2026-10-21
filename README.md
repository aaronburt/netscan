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
go build -o netscan.exe ./cmd/netscan
```

## Usage

### Standard Mode (System Tray)

```powershell
.\netscan.exe
```

Open the dashboard in your browser:
[http://127.0.0.1:9095](http://127.0.0.1:9095)

### Headless Mode (Console)

```powershell
.\netscan.exe -headless
```

### Custom Configuration

```powershell
.\netscan.exe -config path\to\config.json
```

### Checking & Installing Updates

Check GitHub for available releases:

```powershell
.\netscan.exe -check-update
```

Download and apply latest update directly:

```powershell
.\netscan.exe -update
```
