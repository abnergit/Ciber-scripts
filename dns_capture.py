import subprocess

try:
    from scapy.all import *
except ImportError:
    subprocess.run(["pip", "install", "scapy"])
    from scapy.all import *
listados = []
def dns_sniff(pkt):
    # Check if the packet is a DNS packet
    if pkt.haslayer(DNSQR):
        # Extract the source IP address
        try:
	        src_ip = pkt[IP].src
        except:
	        src_ip = "Nao identificado"

	# Extract the destination IP address
        try:
            dst_ip = pkt[IP].dst
        except:
	        dst_ip = "Nao identificado"
        # Extract the domain name
        domain_name = pkt[DNS].qd.qname.decode()
        tipo = "Nao identificado"
        if IP in pkt:
            tipo = pkt[IP].version
        if domain_name not in listados:
            print(f"Version: {tipo} Source IP: {src_ip} Destination IP: {dst_ip} Domain Name: {domain_name}")
            listados.append(domain_name)

# Sniff packets on the wlo1 interface
sniff(iface="wlo1", filter="udp port 53", prn=dns_sniff)
