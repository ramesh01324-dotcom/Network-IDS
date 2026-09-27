# 🛡️ Basic Browser-Based Network Intrusion Detection System (IDS)

A lightweight, real-time Network Intrusion Detection System built with **Python**, **Flask**, **Scapy**, and a modern web-based dashboard. It monitors network traffic, detects active attack vectors (Port Scanning, DoS, Ping Flood, SYN Flood), filters out local background noise, and provides a live alert dashboard with on-demand log exporting.

---

## 🚀 Key Features

* **Real-Time Packet Sniffing**: Uses `Scapy` to capture live IPv4 and IPv6 packets traversing the network interface.
* **Intelligent Threat Detection Engine**: Threshold-based counters detect:
  * **Port Scanning**: Multiple unique ports targeted within a rolling time window.
  * **DoS (Denial of Service)**: High-volume packet floods from a single source IP.
  * **Ping Flood**: Excessive ICMP request floods.
  * **SYN Flood**: Abnormal accumulation of TCP SYN handshake flags.
* **False Positive Reduction**: Integrated white-listing and local subnet filtering to ignore harmless background noise and local traffic.
* **Modern Web Dashboard**: Built with Flask and a responsive dark-themed UI featuring auto-refreshing logs and high-visibility red threat alert banners.
* **On-Demand Log Export**: A dedicated UI button allowing users to instantly download captured traffic data and alerts as a formatted text file.

---

## 🛠️ Tech Stack

* **Backend**: Python, Flask, Scapy, Multi-threading
* **Frontend**: HTML5, CSS3, JavaScript (AJAX Polling)
* **Environment**: Kali Linux / Linux (Requires administrative privileges for raw packet sniffing)

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/network-ids.git](https://github.com/your-username/network-ids.git)
   cd network-ids
