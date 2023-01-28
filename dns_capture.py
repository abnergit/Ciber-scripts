import subprocess

try:
    from scapy.all import *
except ImportError:
    subprocess.run(["pip", "install", "scapy"])
    from scapy.all import *

def dns_sniff(pkt):
    # Check if the packet is a DNS packet
    if pkt.haslayer(DNSQR):
        # Extract the source IP address
        src_ip = pkt[IP].src
        # Extract the destination IP address
        dst_ip = pkt[IP].dst
        # Extract the domain name
        domain_name = pkt[DNS].qd.qname.decode()
        print(f"Source IP: {src_ip} Destination IP: {dst_ip} Domain Name: {domain_name}")

# Sniff packets on the wlo1 interface
sniff(iface="wlo1", filter="udp port 53", prn=dns_sniff)
