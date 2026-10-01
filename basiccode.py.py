from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def show_packet(packet):

        if IP in packet:
                print("source IP:", packet[IP].src)
                print("destination IP:", packet[IP].dst)

                if TCP in packet:
                        print("protocol: TCP")
                        print("source Port:", packet[TCP].sport)
                        print("destination Port:", packet[TCP].dport)
                elif UDP in packet:
                        print("protocol: UDP")
                        print("source Port:", packet[UDP].sport)
                        print("destination Port:", packet[UDP].dport)
                elif ICMP in packet:
                        print("protocol: ICMP")
                else:
                        print("protocol: other")

                if Raw in packet:
                        print("payload:", packet[Raw].load)

print ("starting capture of packets...")

sniff (prn=show_packet, count=50, store=False)

