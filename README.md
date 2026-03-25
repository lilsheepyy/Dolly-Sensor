# Dolly Sensor
<img width="1859" height="958" alt="imagen" src="https://github.com/user-attachments/assets/134c41ba-5565-43e4-86a2-d87ee31b38b5" />


Go-based sFlow collector focused on inbound DDoS visibility.

It receives sFlow v5 datagrams, decodes the inner packet headers carried in `FLOWSAMPLE` raw packet header records, applies protocol-specific filters, and serves a small web dashboard with live protocol counts and alert state.

## What It Does

- Receives sFlow on the configured UDP collector address
- Decodes inner Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, and SSH details from sampled packets
- Only counts inbound traffic whose destination IP belongs to your configured `local.owned_cidrs`
- Applies multiple filters at once:
  - `ssh`
  - `dnsamp`
  - `ntpamp`
  - `ftp`
  - `inbound`
- Optionally issues BGP FlowSpec actions through an external CLI such as `gobgp`
- Serves a dashboard over HTTP

## Build

```bash
go build ./...
```

## Run

```bash
go run .
```

Open:

```txt
http://127.0.0.1:8080
```

## Configuration

Runtime config lives in `config.json`.

Main sections:

- `sflow.collector`
- `http.listen`
- `store.max_recent_packets`
- `bgpflowspec`
- `local.owned_cidrs`
- `filters.active`

Example:

```json
{
  "sflow": {
    "sampling": 1,
    "polling": 30,
    "collector": {
      "ip": "127.0.0.1",
      "udpport": 6343
    }
  },
  "http": {
    "listen": "127.0.0.1:8080"
  },
  "store": {
    "max_recent_packets": 4096
  },
  "bgpflowspec": {
    "enabled": false,
    "command": "gobgp",
    "max_workers": 8,
    "queue_size": 256
  },
  "local": {
    "owned_cidrs": [
      "127.0.0.0/8",
      "192.168.1.0/24"
    ]
  },
  "filters": {
    "active": [
      "ssh",
      "dnsamp",
      "ntpamp",
      "ftp",
      "inbound"
    ]
  }
}
```

## Filter Behavior

- `ssh`
  - applies to all inbound packets with `dst port 22`
  - uses per-destination-IP Z-Score anomaly detection over PPS
  - destination profiles are persisted to `data/ssh_profiles.json`
- `dnsamp`
  - applies only to packets with `src port 53`
  - trusted resolver IPs are allowed
  - untrusted `src ip + src port 53` can be blocked
- `ntpamp`
  - applies only to packets with `src port 123`
  - trusted NTP server IPs are allowed
  - untrusted `src ip + src port 123` can be blocked
- `ftp`
  - applies only to incoming packets with `dst port 21`
  - non-TCP packets to `dst port 21` are blocked by source IP
  - packets to `dst port 21` with `src port` in `1-1024` are blocked by source IP
- `inbound`
  - applies to all inbound packets to owned destination IPs
  - keeps a per-destination global profile with pps and mbps mean/deviation
  - tracks dominant protocols per destination profile
  - emits anomaly alerts when pps or mbps Z-Score exceeds threshold

## Notes

- This project is made with AI, reviewed by me.
- This project consumes sFlow; it does not sniff raw host interfaces directly.
- SSH traffic profiling is persisted to `data/ssh_profiles.json` and restored on restart.
- FlowSpec commands are executed through the configured external command template.

# Any pulls are welcome, thanks for reading, using or developing this!
