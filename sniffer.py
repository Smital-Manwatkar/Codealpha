from scapy.all import sniff, IP

# Callback function to process each captured packet
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = bytes(packet[IP].payload)

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto}")
        print(f"Payload: {payload[:50]}")  # show first 50 bytes
        print("-" * 50)

# Capture 10 packets
sniff(count=10, prn=process_packet)