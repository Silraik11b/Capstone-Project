# this script sniffs tcp packets and writes them to "testpcapfile.pcap" file

from scapy.all import sniff, wrpcap
packets=sniff(count=10000, filter="tcp")
wrpcap("/home/labsuser/testpcapfile.pcap",packets)
