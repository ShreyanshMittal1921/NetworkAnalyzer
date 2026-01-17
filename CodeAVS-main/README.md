# CodeAVS
# Real-Time Network Analyzer using Python and Wireshark

This project leverages Software-Defined Networking (SDN) principles to monitor, detect, and respond to network traffic anomalies in real-time. It enhances network security through DDoS attack detection (SYN flood) and offers both forensic logging and live web-based visualization.

## 🔐 Key Features

* ✅ Real-time network traffic monitoring with Mininet.
* ✅ Anomaly detection targeting SYN flood DDoS attacks.
* ✅ Alerts shown on terminal and live web interface.
* ✅ IP blocking using iptables when attacks are detected.
* ✅ Logs suspicious traffic in structured JSON format.
* ✅ Live traffic visualizations using dynamic charts.

---

## 🛠 Tools and Technologies

| Tool          | Purpose                                |
| ------------- | -------------------------------------- |
| **Mininet**   | Simulated network topology with SDN    |
| **Scapy**     | Packet sniffing and analysis           |
| **Wireshark** | Packet validation and deep inspection  |
| **Flask**     | Backend server for dashboard           |
| **Chart.js**  | Real-time line/pie chart visualization |
| **iptables**  | Blocking suspicious IPs dynamically    |

---

## 📦 Requirements

* Ubuntu 22.04 (VM recommended)
* Python 3.10.6
* Mininet
* `hping3`, `iperf`, and `iptables`
* Python libraries:

  * Flask
  * Scapy
  * Chart.js (frontend)
  * json, time, os, collections (built-in)

Install Python dependencies using:

```bash
pip install -r requirements.txt
```

---

## ▶️ How to Run the System

There are **three main components** to launch for the complete system:

---

### 1. **Launch Custom Mininet Topology**

Run the topology file (e.g., `topology.py`) to simulate your network:

```bash
sudo python3 topology.py
```

✅ This sets up hosts (like h1 to h8) and connects them via SDN.

---

### 2. **Run Real-Time DDoS Detection Script**

Run the detection script (`realtime_attack_detection.py`) inside the h8 host (or the relevant host receiving traffic):

```bash
xterm h8
sudo python3 realtime_attack_detection.py
```

✅ This will:

* Monitor incoming packets.
* Detect potential SYN flood attacks.
* Log alerts to terminal and JSON files.
* Block attacker IPs dynamically.

---

### 3. **Start the Flask Web Dashboard**

From your main machine (not inside Mininet), run:

```bash
python3 app.py
```

✅ This opens a real-time dashboard at `http://localhost:5000/` displaying:

* Line chart of live SYN packets.
* Pie chart of attack source distribution.
* Table of blocked IPs.

---

## 🚀 Testing the System

You can generate test traffic using:

### Example 1: DDoS Simulation with `hping3`

```bash
xterm h1
hping3 -S -p 80 --flood 10.0.0.8
```

### Example 2: Normal Traffic with `iperf`

```bash
xterm h2
iperf -s
xterm h3
iperf -c 10.0.0.2
```

---

## 📁 File Structure Overview

| File                           | Purpose                                       |
| ------------------------------ | --------------------------------------------- |
| `topology.py`                  | Custom Mininet topology script                |
| `realtime_attack_detection.py` | Packet sniffer + DDoS detection + blocking    |
| `app.py`                       | Flask web server to display dashboard         |
| `requirements.txt`             | List of required Python packages              |

---

## 📌 Notes

* This system assumes the attacking target is host `h8` (`10.0.0.8`) by default. Adjust IPs as per your topology.
* If iptables rules persist after blocking, you may clear them with:

```bash
sudo iptables -F
```

* Run detection script as **root** due to packet sniffing and firewall manipulation.

---

## 🤝 Contribution

Feel free to fork this project, suggest improvements, or contribute to future versions with advanced ML-based detection or a more scalable dashboard.

---
