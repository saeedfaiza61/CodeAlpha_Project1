from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw

captured_packets = []

def show_packet(packet):
    captured_packets.append(packet)  

    if IP in packet:
        print("------------------------------")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if TCP in packet:
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)
        elif UDP in packet:
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)
        elif ICMP in packet:
            print("Protocol: ICMP")
        else:
            print("Protocol: Other")

        if Raw in packet:
            print("Payload:", packet[Raw].load)

print("Starting packet capture...")
sniff(prn=show_packet, count=40, store=False, filter="tcp port 443")  


wrpcap("captured_traffic.pcap", captured_packets)
print("Saved to captured_traffic.pcap")