# Dolly Sensor

Minimal Go sFlow collector for inbound profiling and DDoS alerts.

## Features

- Listens for sFlow v5 datagrams on `127.0.0.1:6343`
- Decodes packet headers from raw packet header records
- Keeps **global inbound profiles per owned destination IP**
- Tracks:
  - average Mbps + Mbps deviation
  - average PPS + PPS deviation
  - top protocols per destination IP
- Emits inbound anomaly alerts with Z-Score logic
- Serves dashboard at `127.0.0.1:8080`

## Run

```bash
go run .
```

## Build

```bash
go build ./...
```

## Config

Edit `config.json`:

- `sflow.collector.ip`
- `sflow.collector.udpport`
- `http.listen`
- `store.max_recent_packets`
- `local.owned_cidrs`
