from scapy.all import sniff, TCP, IP, send, RandIP
import random
for i in range(100):
        pkt = IP(dst="172.31.15.86") / TCP(sport=random.randint(32768, 60999), dport=1013, flags="S")
        send(pkt)

