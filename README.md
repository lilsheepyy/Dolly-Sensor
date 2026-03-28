# 🛡️ Dolly-Sensor v1.0.0 | High-Performance DDoS Mitigation & sFlow Analyzer

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/lilsheepyy/Dolly-Sensor/releases/tag/v1.0.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/Dolly-Sensor)](https://goreportcard.com/report/github.com/lilsheepyy/Dolly-Sensor)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Unix-lightgrey.svg)](https://github.com/lilsheepyy/Dolly-Sensor)

**Dolly-Sensor** is a carrier-grade, open-source network security solution designed for real-time **DDoS detection** and automated **BGP Mitigation**. Powered by a high-performance sharded engine written in Go, it analyzes **sFlow** samples to identify malicious patterns and protect infrastructure with surgical precision.

---

## 🚀 Key Features

*   **⚡ Ultra-High Throughput:** Process hundreds of thousands of PPS using a massively parallel **Sharded Engine** (optimized for multi-core CPUs like AMD Ryzen & EPYC).
*   **📊 War Room Dashboard:** Real-time visibility with 6 dynamic charts per IP, tracking Protocols, TCP Flags, TTL distributions, and Top Talkers.
*   **🛡️ Intelligent Mitigation:** Automated response via **BGP Flowspec** and **RTBH** with programmable rule withdrawal (auto-cleanup after 60s).
*   **🧠 TrustScore System:** Advanced behavioral reputation engine that rewards legitimate users and penalizes attackers based on TCP handshake success.
*   **🔍 Protocol-Specific Inspection:** Dedicated filters for **FTP (Ports 20 & 21)** and **SSH**, detecting malformed commands, brute force, and protocol mismatches.

---

## 💻 Hardware Ready Architecture

Dolly-Sensor is designed to scale with your infrastructure. Whether you are running on a specialized appliance or a standard workstation, the system adapts:

*   **Agnostic Scalability:** Automatically detects CPU topology and distributes the workload across configurable **Shards** (default: 64).
*   **Precision Timing:** Uses sFlow packet timestamps for PPS calculation, ensuring 100% accuracy regardless of CPU load or network jitter.
*   **Memory Efficient:** Optimized heap allocation and ring buffers to handle massive traffic bursts on systems with limited RAM (8GB+ recommended).

---

## 🛠️ Installation & Setup

### 1. Prerequisites
Ensure you have **Go 1.21+** installed and **GoBGP** if you intend to use automated BGP mitigation.

### 2. Clone the Repository
```bash
sudo git clone https://github.com/lilsheepyy/Dolly-Sensor.git
cd Dolly-Sensor
```

### 3. Configuration
Rename the template and adjust it to your network environment:
```bash
sudo cp rename-me.config.json config.json
sudo nano config.json
```
*Configure your `owned_cidrs`, `collector_port`, and `bgp_peers`.*

### 4. Build and Run
```bash
# Compile the production binary
sudo go build -o dolly-sensor main.go

# Execute the sensor
sudo ./dolly-sensor
```

---

## 📈 Monitoring & API

Access the **War Room Dashboard** at `http://YOUR_IP:8080`.

*   **Overview:** Global PPS/Mbps load and active critical alerts.
*   **IP Insight:** Deep-dive into specific protected targets with 6-layer traffic analysis.
*   **Mitigation:** View and manage active BGP announcements and blocklists.
*   **Inspector:** Real-time stream of sampled packets with fuzzy filtering.

---

## 🛡️ Mitigation Logic (BGP Flowspec)

Dolly-Sensor doesn't just detect; it acts. When a threat is confirmed:
1.  A **Flowspec** rule is generated (Source IP + Protocol + Port).
2.  The rule is announced to your edge routers via **GoBGP**.
3.  The sensor monitors the attack and **automatically withdraws** the rule after the configured duration (default: 60s), keeping your routing table clean.

---

## 🤝 Contributing

We welcome contributions to make Dolly-Sensor the best open-source DDoS protection tool.
1.  Fork the Project.
2.  Create your Feature Branch (`sudo git checkout -b feature/AmazingFeature`).
3.  Commit your Changes (`sudo git commit -m 'Add some AmazingFeature'`).
4.  Push to the Branch (`sudo git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

**Keywords:** *DDoS Protection, sFlow Analyzer, BGP Flowspec, RTBH, Network Security, Intrusion Detection System, Go Performance, Traffic Profiling, Cybersecurity, Ryzen Optimized.*
