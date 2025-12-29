"""
OS Fingerprinting Module
Simple OS detection based on TTL and response patterns.
Not highly accurate, for basic assessment only.
"""

from scapy.all import IP, ICMP, sr1

def fingerprint_os(host):
    """Simple OS fingerprinting using TTL."""
    pkt = IP(dst=host)/ICMP()
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp:
        ttl = resp[IP].ttl
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"
    return "No response"