#!/usr/bin/env python3
"""
Enhanced ARP Network Scanner - Advanced tool for Windows to scan local networks
Features: Multi-threading, MAC vendor lookup, hostname resolution, continuous monitoring
Author: Enhanced with professional networking features
Usage: python arp_scanner.py [options]
"""

import os
import sys
import subprocess
import re
import ipaddress
import argparse
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class ARPScanner:
    def __init__(self):
        self.results = {}
        self.verbose = True
        self.initial_entries = {}
        self.current_network = None
        
    def ping_ip(self, ip):
        """Send a single ping to trigger ARP entry"""
        try:
            subprocess.run(
                ["ping", "-n", "1", "-w", "500", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass
    
    def get_arp_table(self):
        """Get current ARP table from Windows"""
        try:
            result = subprocess.run(
                ["arp", "-a"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""
    
    def parse_arp_entries(self, arp_output):
        """Parse ARP table output and extract IP/MAC pairs"""
        entries = {}
        
        # Regex to match IP and MAC address lines
        pattern = r'^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})\s+\w+\s*$'
        
        for line in arp_output.splitlines():
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                ip, mac = match.groups()
                # Skip broadcast and multicast addresses
                if mac.lower() not in ['ff-ff-ff-ff-ff-ff', '01-00-5e-00-00-16']:
                    entries[ip] = mac.upper()
        
        return entries
    
    def get_mac_vendor(self, mac):
        """Lookup MAC address vendor using OUI database"""
        try:
            # Remove any non-hex characters and take first 6 chars (OUI)
            oui = re.sub(r'[^a-f0-9]', '', mac.lower())[:6]
            
            # Try to find vendor in local OUI database
            oui_file = os.path.join(os.path.dirname(__file__), 'oui.txt')
            if os.path.exists(oui_file):
                with open(oui_file, 'r') as f:
                    for line in f:
                        if oui in line.lower():
                            return line.strip().split('\t')[-1]
            
            # Fallback to online API if available
            try:
                import requests
                response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
                if response.status_code == 200:
                    return response.text
            except:
                pass
        except:
            pass
        return "Unknown"
    
    def resolve_hostname(self, ip):
        """Attempt to resolve hostname for IP"""
        try:
            result = subprocess.run(
                ["nslookup", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Name:" in line:
                        return line.split("Name:")[1].strip()
        except:
            pass
        return ""
    
    def scan_network(self, network_cidr, threads=50):
        """Scan network range using ARP ping with multi-threading"""
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            self.current_network = network
        except ValueError as e:
            print(f"Error: Invalid network format '{network_cidr}'. Use CIDR notation like 192.168.1.0/24")
            return {}
        
        print(f"\n[*] Scanning network: {network}")
        print(f"[*] Total IPs to scan: {network.num_addresses - 2}")
        print(f"[*] Using {threads} threads...")
        
        # Get initial ARP table
        initial_arp = self.get_arp_table()
        self.initial_entries = initial_entries = self.parse_arp_entries(initial_arp)
        
        # Ping all IPs in the network using threads
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.ping_ip, ip): ip for ip in network.hosts()}
            
            if self.verbose:
                completed = 0
                total = len(futures)
                for future in as_completed(futures):
                    completed += 1
                    if completed % 100 == 0:
                        print(f"[*] Processed {completed}/{total} IPs...")
        
        # Wait a moment for ARP table to update
        time.sleep(2)
        
        # Get updated ARP table
        final_arp = self.get_arp_table()
        final_entries = self.parse_arp_entries(final_arp)
        
        # Store results
        self.results = final_entries
        
        # Display results
        self.display_results(final_entries)
        
        return final_entries
    
    def display_results(self, entries):
        """Display results with additional information"""
        if entries:
            print(f"\n[+] Found {len(entries)} active devices:")
            print("-" * 90)
            print(f"{'IP Address':<15} {'MAC Address':<18} {'Vendor':<25} {'Hostname':<20} {'Status'}")
            print("-" * 90)
            
            for ip in sorted(entries.keys(), key=lambda x: ipaddress.IPv4Address(x)):
                mac = entries[ip]
                vendor = self.get_mac_vendor(mac)
                hostname = self.resolve_hostname(ip)
                status = "NEW" if ip not in self.initial_entries else "EXISTING"
                print(f"{ip:<15} {mac:<18} {vendor[:25]:<25} {hostname[:20]:<20} {status}")
        else:
            print("\n[!] No devices found. Try running as Administrator or check network connectivity.")
    
    def continuous_monitor(self, network_cidr, interval=60, threads=50):
        """Continuously monitor network for changes"""
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            self.current_network = network
        except ValueError as e:
            print(f"Error: Invalid network format '{network_cidr}'")
            return
        
        print(f"\n[*] Starting continuous monitoring of {network}")
        print("[*] Press Ctrl+C to stop monitoring\n")
        
        previous_devices = {}
        
        try:
            while True:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n=== Scan at {current_time} ===")
                
                # Run scan
                current_devices = self.scan_network(network_cidr, threads)
                
                # Detect changes
                new_devices = {ip: mac for ip, mac in current_devices.items() if ip not in previous_devices}
                gone_devices = {ip: mac for ip, mac in previous_devices.items() if ip not in current_devices}
                
                if new_devices:
                    print("\n[+] New devices detected:")
                    for ip, mac in new_devices.items():
                        vendor = self.get_mac_vendor(mac)
                        hostname = self.resolve_hostname(ip)
                        print(f"  {ip} - {mac} - {vendor[:30]} - {hostname}")
                
                if gone_devices:
                    print("\n[-] Devices no longer present:")
                    for ip, mac in gone_devices.items():
                        print(f"  {ip} - {mac}")
                
                previous_devices = current_devices
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
    
    def save_results(self, filename, format_type="txt"):
        """Save results to file in specified format"""
        if not self.results:
            print("[!] No results to save.")
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if format_type.lower() == "json":
            filename = filename if filename.endswith('.json') else f"{filename}.json"
            data = {
                "scan_time": timestamp,
                "network_scanned": str(self.current_network),
                "total_devices": len(self.results),
                "devices": []
            }
            
            for ip, mac in self.results.items():
                data["devices"].append({
                    "ip_address": ip,
                    "mac_address": mac,
                    "vendor": self.get_mac_vendor(mac),
                    "hostname": self.resolve_hostname(ip),
                    "first_seen": "Existing" if ip in self.initial_entries else "New"
                })
            
            try:
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"[+] Results saved to {filename}")
            except Exception as e:
                print(f"[!] Error saving JSON file: {e}")
        
        elif format_type.lower() == "txt":
            filename = filename if filename.endswith('.txt') else f"{filename}.txt"
            
            try:
                with open(filename, 'w') as f:
                    f.write(f"ARP Network Scan Results\n")
                    f.write(f"Scan Time: {timestamp}\n")
                    f.write(f"Network: {self.current_network}\n")
                    f.write(f"Total Devices: {len(self.results)}\n")
                    f.write("-" * 90 + "\n")
                    f.write(f"{'IP Address':<15} {'MAC Address':<18} {'Vendor':<25} {'Hostname':<20} {'Status'}\n")
                    f.write("-" * 90 + "\n")
                    
                    for ip in sorted(self.results.keys(), key=lambda x: ipaddress.IPv4Address(x)):
                        mac = self.results[ip]
                        vendor = self.get_mac_vendor(mac)
                        hostname = self.resolve_hostname(ip)
                        status = "EXISTING" if ip in self.initial_entries else "NEW"
                        f.write(f"{ip:<15} {mac:<18} {vendor[:25]:<25} {hostname[:20]:<20} {status}\n")
                
                print(f"[+] Results saved to {filename}")
            except Exception as e:
                print(f"[!] Error saving TXT file: {e}")

def get_default_network():
    """Try to detect the default network interface"""
    try:
        # Get default gateway
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line and "On-link" not in line:
                parts = line.split()
                if len(parts) >= 3:
                    gateway = parts[2]
                    # Convert to network address
                    network_parts = gateway.split(".")
                    if len(network_parts) == 4:
                        network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
                        return network
    except Exception:
        pass
    
    return None

def clear_arp_cache():
    """Clear the ARP cache"""
    try:
        result = subprocess.run(
            ["arp", "-d"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            print("[+] ARP cache cleared successfully")
            return True
        else:
            print("[!] Failed to clear ARP cache. Run as Administrator.")
            return False
    except Exception as e:
        print(f"[!] Error clearing ARP cache: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced ARP Network Scanner for Windows with advanced features",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-n", "--network",
        help="Network to scan in CIDR notation (e.g., 192.168.1.0/24)"
    )
    
    parser.add_argument(
        "-c", "--clear",
        action="store_true",
        help="Clear ARP cache before scanning (requires Admin privileges)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output filename (without extension)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["txt", "json", "both"],
        default="txt",
        help="Output format: txt, json, or both (default: txt)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - minimal output"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="Number of threads to use for scanning (default: 50)"
    )
    
    parser.add_argument(
        "-m", "--monitor",
        action="store_true",
        help="Enable continuous monitoring mode"
    )
    
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=60,
        help="Monitoring interval in seconds (default: 60)"
    )
    
    parser.add_argument(
        "--vendor-lookup",
        action="store_true",
        help="Enable MAC vendor lookup (requires internet connection for full database)"
    )
    
    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Enable hostname resolution for discovered devices"
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("\n" + "=" * 60)
        print("    Enhanced ARP Network Scanner - Advanced Version")
        print("=" * 60)
    
    scanner = ARPScanner()
    scanner.verbose = not args.quiet
    
    # Clear ARP cache if requested
    if args.clear:
        clear_arp_cache()
        time.sleep(1)
    
    # Determine network to scan
    network = args.network
    if not network:
        detected_network = get_default_network()
        if detected_network:
            if args.quiet:
                network = detected_network
            else:
                response = input(f"Detected network: {detected_network}. Use this? [Y/n]: ").strip().lower()
                if response in ['', 'y', 'yes']:
                    network = detected_network
        
        if not network:
            while True:
                network = input("Enter network in CIDR notation (e.g., 192.168.1.0/24): ").strip()
                try:
                    ipaddress.IPv4Network(network, strict=False)
                    break
                except ValueError:
                    print("Invalid network format. Please try again.")
    
    # Run the scan or monitoring
    if args.monitor:
        scanner.continuous_monitor(network, args.interval, args.threads)
    else:
        results = scanner.scan_network(network, args.threads)
        
        # Save results if requested
        if args.output and results:
            if args.format in ["txt", "both"]:
                scanner.save_results(args.output, "txt")
            if args.format in ["json", "both"]:
                scanner.save_results(args.output, "json")
        
        # Ask for rescan
        if not args.quiet and results:
            while True:
                response = input("\nWould you like to rescan? [y/N]: ").strip().lower()
                if response in ['y', 'yes']:
                    print("\nRescanning...")
                    scanner.scan_network(network, args.threads)
                    if args.output:
                        if args.format in ["txt", "both"]:
                            scanner.save_results(f"{args.output}_rescan", "txt")
                        if args.format in ["json", "both"]:
                            scanner.save_results(f"{args.output}_rescan", "json")
                else:
                    break
    
    if not args.quiet:
        print("\n[*] Scan complete!")

if __name__ == "__main__":
    main()