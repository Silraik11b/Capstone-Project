
print("Welcome to Py Snortlings 2.0!")
print("This program will sniff packets on your network and alert you if it sees any anamolous activity.")
print("It will suggest both snort and UFW rules to alert or block the traffic.")
print("It can parse through pcap files or sniff live traffic.")
print("---------------------------------------------------------")
print("---------------------------------------------------------")


from scapy.all import sniff, rdpcap, IP, TCP #import scapy modules
import time #import time module to take care of  time lapse
import logging #logging module, allowing you to track events, debug issues, and store alerts
from datetime import datetime

# Set up logging
logging.basicConfig(filename="syn_alerts.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S") #sets up logging for your script, meaning all INFO-level messages (including alerts) will be stored in the "dos_alerts.log"

syn_count = {}
syn_total = 0 #initialize global variable syn_count to 0. syn_count is used to count the number of SYN packets.
start_time = time.time() #save current time into start_time variable.This is also a global variable.

# Fixed Thresholds
THRESHOLD1 = 80  # Adjust threshold for live capture based on expected traffic
THRESHOLD2 = 100 # adjust threshold for pcap file 

def detect_syn_pcap(packet): #define a function named detect_syn_pcap(), takes packet as an argument from a pcap file
    global syn_total, syn_count # declare global variables
    # Ensure packet has both IP and TCP layers and SYN packet is set
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S": 
        src_ip = packet[IP].src # save the source ip to "src_ip" variable
        syn_count[src_ip] = syn_count.get(src_ip, 0) + 1 # This ensures src_ip starts at 0 if it’s not already in syn_count, then increments.
        syn_total += 1  # Track total SYN packets globally
    

def detect_syn_live(packet): #define a function named detect_syn_live(), takes packet as an argument from live capture
    global syn_total, start_time # declare global variables
    # Ensure packet has both IP and TCP layers and SYN packet is set
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S": 
        syn_total += 1  # Track total SYN packets globally
        print("syncount: ", syn_total, time.time()) #print total # of SYN packets encountered so far

    if time.time() - start_time >= 1: # This line checks if at least 1 second has passed since the last reset (start_time). If so, it prints the number of detected SYN pa>
        print(f"SYN packets detected: {syn_total}/sec")
        if syn_total > THRESHOLD1:  #if total # of SYN packets per sec is > the threshold, print and log the alert message
            alert_msg = f"🚨 Possible SYN flood attack detected! Total SYN packets/sec: {syn_total} (Threshold: {THRESHOLD1})"
            # Get current date and time
            now = datetime.now()
            # Format and print
            print("Current Date and Time:", now.strftime("%Y-%m-%d %H:%M:%S"))
            print(alert_msg)
            logging.info(alert_msg)

            # Alert if SYN flood threshold is exceeded. Monitors TCP SYN packets from any source to the home network.
# Targets packets with SYN flag set (potential flood attempts).Triggers an alert if an IP sends more than 20 SYN packets in 1 second.
#sid:1000001 → Unique rule identifier.rev:1 → Revision number for the rule.
            snort_rule = f'alert tcp any any -> $HOME_NET any (flags:S; msg:"Possible SYN flood attack detected"; threshold: type threshold, count {syn_total}, seconds 1;>
            print(f"🔍 Suggested Snort Rule:\n{snort_rule}")

            # Suggested UFW Rule (Blocking excessive SYN traffic)
            ufw_rule = "sudo ufw limit proto tcp from any to any port 1013"
            print(f"🛡️ Suggested UFW Rule:\n{ufw_rule}")

        # Reset counter and timer
        syn_total = 0
        start_time = time.time()

def analyze_pcap(file_path): #define a function to start analyzing a pcap file
    packets = rdpcap(file_path) #Reads a PCAP file using rdpcap(file_path), loading all packets into a list.
    n = len(packets)
    print("total number of packets in this file: ", n)
    for packet in packets: #Loops through each packet from the PCAP file. Calls detect_syn(packet) to analyze each packet individually for SYN flood detection
        detect_syn_pcap(packet) 
    percentage = (syn_total/n) * 100 #calculate percentage of SYN packets in the file and print them
    print(f"Number of SYN packets in the file: {syn_total}({percentage})%") 

    for ip, count in syn_count.items(): #iterate through syn_count dictionary to find out if any of the ip address' SYN count exceeds THRESHOLD2. If yes, print an
# alert message and log the message
        print(f"No: SYN packets per {ip}: {count} ")
        if count > THRESHOLD2:
                alert_msg = f"🚨 Possible SYN flood detected from {ip}! Packets/sec: {count} (Threshold: {THRESHOLD2})(filename: {file_path})"
                print(alert_msg)
                logging.info(alert_msg)
def start_live_capture(): # define a function to start sniffing on live packet capture
    sniff(filter="tcp", prn=detect_syn_live, store=0) # Captures only TCP packets.
#prn=detect_dos → Calls detect_syn() function for each packet to analyze SYN floods.
#store=0 → Prevents storing packets in memory (same as store=False for efficiency).

# Choose mode: PCAP file analysis or live capture
mode = input("Enter mode (pcap/live): ").strip().lower() #strip the whitespaces from the mode selected and convert into lowercase
if mode == "pcap": #if pcap, then enter filepath for the pcap file to be analyzed
    file_path = input("Enter PCAP file path: ").strip()
    print("ready to analyze: ", file_path)
    analyze_pcap(file_path) # calling analyze_pcap(file_path) function
elif mode == "live": #calling start_live_capture() function if mode selected is "live"
    start_live_capture()
else:
    print("Invalid mode! Choose 'pcap' or 'live'.") #choose either pcap or live or its an invalid mode


