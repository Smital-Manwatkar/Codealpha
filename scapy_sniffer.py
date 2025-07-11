from scapy.all import sniff, IP, TCP, UDP

# Process and display each captured packet
def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto


        # Identify protocol
        if proto_num == 6:
            proto_name = "TCP"
        elif proto_num == 17:
            proto_name = "UDP"
        else:
            proto_name = f"Other ({proto_num})"

        payload = bytes(packet[IP].payload)

        print(f"[+] Packet: {src} --> {dst} | Protocol: {proto_num}")
        print(f"    - Protocol: {proto_name}")
        print(f"    - Payload: {payload[:80]}")  # limit output length
        print("\n Full Packet Breakdown:")
        packet.show()  # 👈 This line shows all layers and fields

        print("-" * 60)

# Start capturing packets
sniff(filter="tcp",prn=process_packet, store=False)



