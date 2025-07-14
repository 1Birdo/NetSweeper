#!/usr/bin/env python3
"""
Enhanced ARP Network Scanner - Simple and reliable tool for Windows to scan local network
Author: Enhanced for workplace use
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

class ARPScanner:
    def __init__(self):
        self.results = {}
        self.verbose = True
        
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
    
    def scan_network(self, network_cidr):
        """Scan network range using ARP ping"""
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
        except ValueError as e:
            print(f"Error: Invalid network format '{network_cidr}'. Use CIDR notation like 192.168.1.0/24")
            return {}
        
        print(f"\n[*] Scanning network: {network}")
        print(f"[*] Total IPs to scan: {network.num_addresses - 2}")  # Exclude network and broadcast
        print("[*] Sending ARP requests...")
        
        # Get initial ARP table
        initial_arp = self.get_arp_table()
        initial_entries = self.parse_arp_entries(initial_arp)
        
        # Ping all IPs in the network
        count = 0
        for ip in network.hosts():
            count += 1
            if self.verbose and count % 50 == 0:
                print(f"[*] Processed {count}/{network.num_addresses - 2} IPs...")
            self.ping_ip(ip)
        
        # Wait a moment for ARP table to update
        time.sleep(2)
        
        # Get updated ARP table
        final_arp = self.get_arp_table()
        final_entries = self.parse_arp_entries(final_arp)
        
        # Store results
        self.results = final_entries
        
        # Display results
        if final_entries:
            print(f"\n[+] Found {len(final_entries)} active devices:")
            print("-" * 60)
            print(f"{'IP Address':<15} {'MAC Address':<18} {'Status'}")
            print("-" * 60)
            
            for ip in sorted(final_entries.keys(), key=lambda x: ipaddress.IPv4Address(x)):
                mac = final_entries[ip]
                status = "NEW" if ip not in initial_entries else "EXISTING"
                print(f"{ip:<15} {mac:<18} {status}")
        else:
            print("\n[!] No devices found. Try running as Administrator or check network connectivity.")
        
        return final_entries
    
    def save_results(self, filename, format_type="txt"):
        """Save results to file in specified format"""
        if not self.results:
            print("[!] No results to save.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type.lower() == "json":
            filename = filename if filename.endswith('.json') else f"{filename}.json"
            data = {
                "scan_time": timestamp,
                "total_devices": len(self.results),
                "devices": self.results
            }
            
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
                    f.write(f"Total Devices: {len(self.results)}\n")
                    f.write("-" * 40 + "\n")
                    
                    for ip in sorted(self.results.keys(), key=lambda x: ipaddress.IPv4Address(x)):
                        f.write(f"{ip}:{self.results[ip]}\n")
                
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
        description="Enhanced ARP Network Scanner for Windows",
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
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("\n" + "=" * 50)
        print("    Enhanced ARP Network Scanner")
        print("=" * 50)
    
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
    
    # Run the scan
    results = scanner.scan_network(network)
    
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
                scanner.scan_network(network)
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
