#!/usr/bin/env python3
"""
Network Scanner Tool - Defensive and Legal Network Assessment Tool
Author: AI Expert (Blue Team Approach)
Description: A Python-based network scanner for authorized security assessments.
Usage: Run with proper permissions and on owned/authorized networks only.
"""

import argparse
import sys
from host_discovery import discover_hosts
from port_scanner import scan_ports
from os_fingerprinting import fingerprint_os
from output import output_results
from utils import parse_ip_range

def main():
    parser = argparse.ArgumentParser(description="Defensive Network Scanner")
    parser.add_argument("target", help="IP address or range (e.g., 192.168.1.0/24 or 192.168.1.1)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g., 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for scanning")
    parser.add_argument("-o", "--output", choices=["terminal", "json", "txt"], default="terminal", help="Output format")
    parser.add_argument("-f", "--file", help="Output file path (for json/txt)")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--no-os", action="store_true", help="Skip OS fingerprinting")
    
    args = parser.parse_args()
    
    # Legal warning
    print("WARNING: This tool is for authorized security assessments only. Ensure you have permission to scan the target network.")
    
    # Parse target
    try:
        ips = parse_ip_range(args.target)
    except ValueError as e:
        print(f"Error parsing target: {e}")
        sys.exit(1)
    
    # Discover hosts
    live_hosts = discover_hosts(ips)
    
    # Scan ports and gather data
    results = {}
    for host in live_hosts:
        results[host] = {}
        if not args.no_os:
            results[host]["os"] = fingerprint_os(host)
        open_ports = scan_ports(host, args.ports, args.threads, not args.no_banner)
        results[host]["open_ports"] = open_ports
    
    # Output results
    output_results(results, args.output, args.file)

if __name__ == "__main__":
    main()