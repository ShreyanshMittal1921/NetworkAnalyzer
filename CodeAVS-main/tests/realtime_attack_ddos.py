import json
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import time

# === Configuration ===
ALERT_THRESHOLD = 100          # Total SYNs to trigger alert
TIME_WINDOW = 10               # Time window in seconds
LOG_FILE = "/home/mohd_arsh/CodeAVS/src/logs/detection_logs.json"

# === Initialization ===
syn_count = defaultdict(int)
start_time = time.time()
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def initialize_log_file():
    """Ensure the log file exists with valid JSON and has open permissions."""
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        print(f"Initializing log file: {LOG_FILE}")
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(LOG_FILE, 0o777)  # Read/write/execute for all

def write_to_log(log_entry):
    """Append alert info to the JSON log file and print it."""
    try:
        print(json.dumps(log_entry, indent=4))  # Terminal output
        with open(LOG_FILE, 'r+') as f:
            logs = json.load(f)
            logs.append(log_entry)
            f.seek(0)
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def block_ip(ip_address):
    """Block the suspicious IP using iptables."""
    try:
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        print(f"Blocked IP: {ip_address}")
    except Exception as e:
        print(f"Failed to block {ip_address}: {e}")

def analyze_packet(packet):
    global start_time
    # Only analyze TCP SYN packets to h8
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 'S' and packet[IP].dst == '10.0.0.8':
            src_ip = packet[IP].src
            syn_count[src_ip] += 1

            current_time = time.time()
            if current_time - start_time > TIME_WINDOW:
                total_syns = sum(syn_count.values())
                if total_syns > ALERT_THRESHOLD:
                    # Log and print the alert
                    log_entry = {
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "alert": "Potential DDoS attack detected on host 8!",
                        "total_syns": total_syns,
                        "sources": dict(syn_count)
                    }
                    write_to_log(log_entry)

                    # Block attackers
                    for ip, count in syn_count.items():
                        if count > ALERT_THRESHOLD / len(syn_count):  # Customize per-IP logic
                            block_ip(ip)

                # Reset for the next window
                syn_count.clear()
                start_time = current_time

# === Start Monitoring ===
initialize_log_file()
print("Starting real-time DDoS detection, logging, and IP blocking on host 8...")
sniff(iface='h8-eth0', prn=analyze_packet)
