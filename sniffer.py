from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw

LOG_FILE = "network_traffic.txt"

def process_packet(packet):
    # 1. IP aur Protocol type
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = "IPv4"
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = "IPv6"
    else:
        return  

    # 2. Port aur Transport Protocol
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        src_port = "N/A"
        dst_port = "N/A"
        protocol = "Other"

    # 3. Asli DATA (Payload) nikalna
    payload_info = ""
    if packet.haslayer(Raw):
        # Raw layer mein data hota hai
        raw_data = packet[Raw].load
        try:
            # Data ko padhne layak text mein convert (decode) karna
            readable_data = raw_data.decode('utf-8', errors='ignore')
            # Kachra hatane ke liye sirf normal characters ko rakhenge
            clean_data = "".join([c for c in readable_data if c.isprintable()])
            
            if clean_data:
                # Agar data bohot bada hai, toh sirf pehle 60 characters dikhayenge
                if len(clean_data) > 60:
                    payload_info = f"\n   [>> DATA >>] {clean_data[:60]}..."
                else:
                    payload_info = f"\n   [>> DATA >>] {clean_data}"
        except:
            pass # Agar data decode nahi hua (encrypted hai), toh ignore karo

    # 4. Output formatting
    log_entry = f"[{ip_version} | {protocol}] {src_ip}:{src_port}  --->  {dst_ip}:{dst_port}{payload_info}"
    
    # 5. Screen par dikhao aur File mein save karo
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

print("Deep Packet Inspection ON! Data scan ho raha hai...")
print("Rokane ke liye 'Ctrl + C' dabayein.")
sniff(prn=process_packet)