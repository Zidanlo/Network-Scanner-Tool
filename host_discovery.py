"""
Host Discovery Module
Uses ICMP Ping and ARP for live host detection.
Requires scapy.
"""

from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import threading
import time

def ping_host(ip):
    """Ping a single host using ICMP."""
    pkt = IP(dst=ip)/ICMP()
    resp = sr1(pkt, timeout=1, verbose=0)
    return resp is not None

def arp_scan(network):
    """ARP scan for local network (requires root)."""
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    return [received.psrc for sent, received in result]

def discover_hosts(ips):
    """Discover live hosts using Ping and ARP if possible."""
    live_hosts = []
    threads = []
    
    def worker(ip):
        if ping_host(ip):
            live_hosts.append(ip)
    
    # Use threading for Ping
    for ip in ips:
        t = threading.Thread(target=worker, args=(ip,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # If local network, try ARP (check if root)
    try:
        import os
        if os.geteuid() == 0:  # Root check
            arp_hosts = arp_scan(ips[0] + "/24")  # Assume /24 for simplicity
            live_hosts.extend([h for h in arp_hosts if h not in live_hosts])
    except:
        pass  # Skip ARP if not possible
    
    return live_hosts