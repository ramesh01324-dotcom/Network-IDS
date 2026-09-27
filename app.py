from flask import Flask, render_template, jsonify, send_file
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
import threading
import time
import os
from collections import defaultdict

app = Flask(__name__)

packets_data = [] 
alerts = set()

ip_packet_count = defaultdict(int)
ip_ports_touched = defaultdict(set)
ip_icmp_count = defaultdict(int)
ip_syn_count = defaultdict(int)

# Apni Kali IP yahan daal de taaki yeh khud ke traffic ko alert na maane
MY_LOCAL_IP = "10.53.137.109"

def analyze_packet(packet):
    src_ip = None
    dst_ip = None
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return  
    
    # Agar packet khud ke system ka hai toh ignore kar do (False positive rokne ke liye)
    if src_ip == MY_LOCAL_IP or src_ip == "127.0.0.1":
        return

    protocol = "Other"
    dst_port = "N/A"
    
    if packet.haslayer(TCP):
        protocol = "TCP"
        dst_port = packet[TCP].dport
        ip_ports_touched[src_ip].add(dst_port)
        try:
            if packet[TCP].flags & 0x02:
                ip_syn_count[src_ip] += 1
        except:
            if "S" in str(packet[TCP].flags):
                ip_syn_count[src_ip] += 1
            
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = packet[UDP].dport
        ip_ports_touched[src_ip].add(dst_port)
        
    elif packet.haslayer(ICMP) or packet.haslayer("ICMPv6"):
        protocol = "ICMP"
        ip_icmp_count[src_ip] += 1

    ip_packet_count[src_ip] += 1

    suspicious = "No"
    reason = "-"

    if ip_packet_count[src_ip] > 300:
        suspicious = "Yes"
        reason = "DoS Attack (High Traffic)"
        alerts.add(f"ALERT: {src_ip} is doing {reason}")

    elif len(ip_ports_touched[src_ip]) > 30:
        suspicious = "Yes"
        reason = "Port Scanning Detected"
        alerts.add(f"ALERT: {src_ip} is doing {reason}")

    elif ip_icmp_count[src_ip] > 100:
        suspicious = "Yes"
        reason = "Ping Flood Detected"
        alerts.add(f"ALERT: {src_ip} is doing {reason}")

    elif ip_syn_count[src_ip] > 100:
        suspicious = "Yes"
        reason = "SYN Flood Detected"
        alerts.add(f"ALERT: {src_ip} is doing {reason}")

    pkt_info = {
        "src": src_ip,
        "dst": dst_ip,
        "proto": protocol,
        "port": dst_port,
        "suspicious": suspicious,
        "reason": reason
    }
    
    packets_data.insert(0, pkt_info)
    if len(packets_data) > 100:
        packets_data.pop()

def reset_counters():
    global ip_packet_count, ip_ports_touched, ip_icmp_count, ip_syn_count, alerts
    while True:
        time.sleep(15)
        ip_packet_count.clear()
        ip_ports_touched.clear()
        ip_icmp_count.clear()
        ip_syn_count.clear()

def start_sniffer():
    sniff(prn=analyze_packet, store=False)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/get_data")
def get_data():
    return jsonify({"packets": packets_data, "alerts": list(alerts)})

# UI se Download button dabane par file download hogi
@app.route("/download_logs")
def download_logs():
    file_path = "network_traffic.txt"
    with open(file_path, "w") as f:
        f.write("--- NETWORK INTRUSION DETECTION SYSTEM (IDS) LOGS ---\n\n")
        for pkt in packets_data:
            f.write(f"Src: {pkt['src']} | Dst: {pkt['dst']} | Proto: {pkt['proto']} | Port: {pkt['port']} | Suspicious: {pkt['suspicious']} | Reason: {pkt['reason']}\n")
    return send_file(file_path, as_attachment=True)

if __name__ == "__main__":
    t1 = threading.Thread(target=start_sniffer, daemon=True)
    t2 = threading.Thread(target=reset_counters, daemon=True)
    t1.start()
    t2.start()

    print("Advanced IDS Dashboard started at: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000)