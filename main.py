#!/usr/bin/env python3
"""
Local Network Scanner - A comprehensive network scanning tool for local networks

Features:
- Ping sweep to discover live hosts
- Port scanning with service detection
- Custom port ranges and common port sets
- OS detection (basic)
- Output formatting options
- Fast threaded implementation
"""

import os
import platform
import subprocess
import threading
import socket
import sys
import time
import ipaddress
import argparse
from queue import Queue
from datetime import datetime

# Version
VERSION = "1.0.0"

# Configuration
MAX_THREADS = 100
PING_TIMEOUT = 1  # seconds
PORT_SCAN_TIMEOUT = 0.3  # seconds

# Common port sets
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}

TOP_PORTS_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
    # ... (add more up to 100)
]

class NetworkScanner:
    def __init__(self):
        self.live_hosts = Queue()
        self.scan_results = {}
        self.lock = threading.Lock()
        self.scan_start_time = None
        self.scan_end_time = None
        self.running = True

    def ping_host(self, ip):
        """Ping a host to check if it's alive."""
        if not self.running:
            return False

        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", "-w", str(PING_TIMEOUT * 1000), ip]
            result = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            
            if result.returncode == 0:
                with self.lock:
                    self.live_hosts.put(ip)
                    return True
        except Exception:
            pass
        return False

    def scan_port(self, ip, port, timeout=PORT_SCAN_TIMEOUT):
        """Scan a specific port on a host."""
        if not self.running:
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    service = COMMON_PORTS.get(port, "unknown")
                    return port, service
        except Exception:
            pass
        return None

    def detect_os(self, ip):
        """Basic OS detection based on TTL and open ports."""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", ip]
            result = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if "ttl=" in output:
                    ttl = int(output.split("ttl=")[1].split()[0])
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Router/Other"
        except Exception:
            pass
        
        open_ports = self.scan_results.get(ip, {}).get('open_ports', [])
        if 3389 in [p[0] for p in open_ports]:
            return "Windows"
        elif 22 in [p[0] for p in open_ports]:
            return "Linux/Unix"
        return "Unknown"

    def scan_services(self, ip, ports):
        """Scan multiple ports on a host."""
        open_ports = []
        for port in ports:
            if not self.running:
                break
            result = self.scan_port(ip, port)
            if result:
                open_ports.append(result)
        
        if open_ports:
            with self.lock:
                self.scan_results[ip] = {
                    'open_ports': open_ports,
                    'os': self.detect_os(ip)
                }

    def ping_sweep(self, network, progress_callback=None):
        """Perform a ping sweep on a network range."""
        self.scan_start_time = datetime.now()
        total_hosts = network.num_addresses - 2  # Exclude network and broadcast
        
        threads = []
        scanned_hosts = 0
        
        for ip in network.hosts():
            if not self.running:
                break
                
            while threading.active_count() > MAX_THREADS:
                time.sleep(0.1)
                if not self.running:
                    break
            
            t = threading.Thread(target=self.ping_host, args=(str(ip),))
            t.start()
            threads.append(t)
            scanned_hosts += 1
            
            if progress_callback and scanned_hosts % 10 == 0:
                progress = (scanned_hosts / total_hosts) * 100
                progress_callback(progress)
        
        for t in threads:
            t.join()

    def service_scan(self, ports, progress_callback=None):
        """Scan services on all live hosts."""
        total_hosts = self.live_hosts.qsize()
        scanned_hosts = 0
        
        threads = []
        while not self.live_hosts.empty() and self.running:
            ip = self.live_hosts.get()
            
            while threading.active_count() > MAX_THREADS and self.running:
                time.sleep(0.1)
            
            t = threading.Thread(target=self.scan_services, args=(ip, ports))
            t.start()
            threads.append(t)
            scanned_hosts += 1
            
            if progress_callback and scanned_hosts % 1 == 0:
                progress = (scanned_hosts / total_hosts) * 100
                progress_callback(progress)
        
        for t in threads:
            t.join()
        
        self.scan_end_time = datetime.now()

    def stop_scan(self):
        """Stop the ongoing scan."""
        self.running = False

def get_local_network():
    """Attempt to determine the local network automatically."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network_addr = ".".join(local_ip.split(".")[:3]) + ".0/24"
        return ipaddress.IPv4Network(network_addr, strict=False)
    except Exception:
        return None

def print_progress(progress):
    """Callback function to print progress."""
    sys.stdout.write(f"\rProgress: {progress:.1f}%")
    sys.stdout.flush()

def parse_ports(port_spec):
    """Parse port specification string into list of ports."""
    ports = set()
    
    # Handle special cases
    if port_spec.lower() == "all":
        return list(range(1, 65536))
    elif port_spec.lower() == "common":
        return list(COMMON_PORTS.keys())
    elif port_spec.lower() == "top100":
        return TOP_PORTS_100
    
    # Handle ranges and individual ports
    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(
        description="Local Network Scanner - A comprehensive network scanning tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "network",
        nargs="?",
        help="Network to scan in CIDR notation (e.g., 192.168.1.0/24)\n"
             "If not specified, will try to detect local network."
    )
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Ports to scan. Can be:\n"
             " - 'all' for all ports (1-65535)\n"
             " - 'common' for common ports (default)\n"
             " - 'top100' for top 100 ports\n"
             " - Specific ports/ranges (e.g., '22,80,443' or '20-25,80-90')"
    )
    parser.add_argument(
        "-P", "--ping-only",
        action="store_true",
        help="Only perform ping sweep, don't scan ports"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to file"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode, minimal output"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=MAX_THREADS,
        help=f"Maximum threads to use (default: {MAX_THREADS})"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"Local Network Scanner v{VERSION}"
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"\nLocal Network Scanner v{VERSION}")
        print("=" * 50)
    
    # Determine network to scan
    if args.network:
        try:
            network = ipaddress.IPv4Network(args.network, strict=False)
        except ValueError:
            print("Error: Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24)")
            sys.exit(1)
    else:
        network = get_local_network()
        if not network:
            print("Error: Could not detect local network. Please specify manually.")
            sys.exit(1)
        if not args.quiet:
            print(f"[*] Using detected network: {network}")
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("Error: Invalid port specification")
        sys.exit(1)
    
    scanner = NetworkScanner()
    global MAX_THREADS
    MAX_THREADS = args.threads
    
    try:
        # Perform ping sweep
        if not args.quiet:
            print(f"\n[*] Starting ping sweep on {network} (Threads: {MAX_THREADS})")
            print(f"[*] Scanning {network.num_addresses - 2} hosts...")
            scanner.ping_sweep(network, progress_callback=None if args.quiet else print_progress)
            
            live_count = scanner.live_hosts.qsize()
            print(f"\n[*] Found {live_count} live hosts")
        
        # Perform service scan if requested and hosts found
        if not args.ping_only and live_count > 0:
            if not args.quiet:
                print(f"\n[*] Starting service scan on {live_count} hosts (Ports: {args.ports})")
                scanner.service_scan(ports, progress_callback=None if args.quiet else print_progress)
            
            if not args.quiet:
                print("\n\nScan Results:")
                print("=" * 50)
                
                for ip, data in scanner.scan_results.items():
                    print(f"\nHost: {ip}")
                    print(f"OS: {data['os']}")
                    print("Open Ports:")
                    for port, service in sorted(data['open_ports'], key=lambda x: x[0]):
                        print(f"  - Port {port}: {service}")
                
                print("\n" + "=" * 50)
                scan_duration = scanner.scan_end_time - scanner.scan_start_time
                print(f"Scan completed in {scan_duration.total_seconds():.2f} seconds")
        
        # Save results to file if requested
        if args.output:
            with open(args.output, "w") as f:
                f.write(f"Network Scan Results for {network}\n")
                f.write(f"Scan performed at {scanner.scan_start_time}\n\n")
                
                if args.ping_only:
                    f.write("Live Hosts:\n")
                    while not scanner.live_hosts.empty():
                        f.write(f"- {scanner.live_hosts.get()}\n")
                else:
                    for ip, data in scanner.scan_results.items():
                        f.write(f"\nHost: {ip}\n")
                        f.write(f"OS: {data['os']}\n")
                        f.write("Open Ports:\n")
                        for port, service in sorted(data['open_ports'], key=lambda x: x[0]):
                            f.write(f"  - Port {port}: {service}\n")
            
            if not args.quiet:
                print(f"\n[*] Results saved to {args.output}")
    
    except KeyboardInterrupt:
        scanner.stop_scan()
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
