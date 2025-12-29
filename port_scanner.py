"""
Port Scanner Module
Uses TCP Connect Scan to identify open ports and services.
Includes basic banner grabbing.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

def tcp_connect_scan(host, port):
    """Perform TCP Connect Scan on a port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            # Try banner grabbing
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Simple HTTP banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                banner = "No banner"
            sock.close()
            return port, banner
        sock.close()
    except:
        pass
    return None

def scan_ports(host, port_range, max_threads, grab_banner=True):
    """Scan ports on a host using threading."""
    start, end = map(int, port_range.split('-'))
    open_ports = {}
    
    def scan_port(port):
        result = tcp_connect_scan(host, port)
        if result:
            open_ports[port] = result[1] if grab_banner else "Open"
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(scan_port, range(start, end + 1))
    
    return open_ports