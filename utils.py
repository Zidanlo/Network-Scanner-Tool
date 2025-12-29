"""
Utilities Module
Helper functions for IP parsing and more.
"""

import ipaddress

def parse_ip_range(target):
    """Parse IP or CIDR range into list of IPs."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Single IP
        return [target]