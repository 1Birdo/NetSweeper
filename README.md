# Local Network Scanner

A comprehensive, fast, and reliable network scanning tool for discovering live hosts and services on local networks. Built with Python 3 and designed for security professionals, network administrators, and enthusiasts.

## 🚀 Features

- **Fast Ping Sweep**: Multi-threaded host discovery with configurable thread limits
- **Port Scanning**: Comprehensive service detection with customizable port ranges
- **Service Identification**: Automatic detection of common services running on open ports
- **OS Detection**: Basic operating system fingerprinting based on TTL values and open ports
- **Flexible Port Selection**: Support for common ports, top 100 ports, custom ranges, or all ports
- **Progress Tracking**: Real-time progress feedback during scanning operations
- **Output Options**: Console display with optional file output for results
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Graceful Interruption**: Clean shutdown with Ctrl+C handling

## 📋 Requirements

- Python 3.6 or higher
- Standard Python libraries (no external dependencies required)
- Administrative/root privileges may be required for some advanced features

## 🛠️ Installation

1. **Download the script**:
   ```bash
   wget https://github.com/1Birdo/NetSweeper/blob/main/main.py
   # or
   curl -O https://github.com/1Birdo/NetSweeper/blob/main/main.py
   ```

2. **Make it executable** (Linux/macOS):
   ```bash
   chmod +x main.py
   ```

3. **Verify installation**:
   ```bash
   python3 main.py --version
   ```

## 🎯 Usage

### Basic Usage

```bash
# Scan local network (auto-detected)
python3 main.py

# Scan specific network
python3 main.py 192.168.1.0/24

# Ping sweep only (no port scanning)
python3 main.py -P 192.168.1.0/24
```

### Advanced Usage

```bash
# Scan with custom ports
python3 main.py 192.168.1.0/24 -p "22,80,443,3389"

# Scan port ranges
python3 main.py 192.168.1.0/24 -p "20-25,80-90,443"

# Use predefined port sets
python3 main.py 192.168.1.0/24 -p common      # Common ports
python3 main.py 192.168.1.0/24 -p top100     # Top 100 ports
python3 main.py 192.168.1.0/24 -p all        # All ports (1-65535)

# Save results to file
python3 main.py 192.168.1.0/24 -o scan_results.txt

# Quiet mode with custom thread count
python3 main.py 192.168.1.0/24 -q -t 50
```

## 📖 Command Line Options

| Option | Description |
|--------|-------------|
| `network` | Network to scan in CIDR notation (e.g., 192.168.1.0/24). Auto-detected if not specified |
| `-p, --ports` | Ports to scan: 'all', 'common', 'top100', or custom (e.g., '22,80,443' or '20-25') |
| `-P, --ping-only` | Only perform ping sweep, skip port scanning |
| `-o, --output` | Save results to specified file |
| `-q, --quiet` | Quiet mode with minimal output |
| `-t, --threads` | Maximum number of threads to use (default: 100) |
| `-v, --version` | Show version information |
| `-h, --help` | Display help message |

## 🔧 Configuration

### Default Settings

```python
MAX_THREADS = 100           # Maximum concurrent threads
PING_TIMEOUT = 1            # Ping timeout in seconds
PORT_SCAN_TIMEOUT = 0.3     # Port scan timeout in seconds
```

### Common Ports

The tool includes predefined sets of commonly scanned ports:

- **Common Ports**: FTP (21), SSH (22), HTTP (80), HTTPS (443), RDP (3389), etc.
- **Top 100 Ports**: Most frequently used ports in enterprise environments
- **All Ports**: Complete range from 1 to 65535

## 📊 Output Format

### Console Output

```
Local Network Scanner v1.0.0
==================================================
[*] Using detected network: 192.168.1.0/24
[*] Starting ping sweep on 192.168.1.0/24 (Threads: 100)
[*] Scanning 254 hosts...
[*] Found 5 live hosts

[*] Starting service scan on 5 hosts (Ports: common)

Scan Results:
==================================================

Host: 192.168.1.1
OS: Router/Other
Open Ports:
  - Port 22: SSH
  - Port 80: HTTP
  - Port 443: HTTPS

Host: 192.168.1.100
OS: Windows
Open Ports:
  - Port 135: unknown
  - Port 445: SMB
  - Port 3389: RDP

==================================================
Scan completed in 12.34 seconds
```

### File Output

When using the `-o` option, results are saved in a structured text format:

```
Network Scan Results for 192.168.1.0/24
Scan performed at 2024-01-15 14:30:22.123456

Host: 192.168.1.1
OS: Router/Other
Open Ports:
  - Port 22: SSH
  - Port 80: HTTP
  - Port 443: HTTPS

Host: 192.168.1.100
OS: Windows
Open Ports:
  - Port 135: unknown
  - Port 445: SMB
  - Port 3389: RDP
```

## 🚦 Performance Tips

1. **Thread Management**: Adjust thread count based on your system capabilities
   ```bash
   # For faster scans on powerful systems
   python3 ping_sweep_tool.py 192.168.1.0/24 -t 200
   
   # For resource-constrained systems
   python3 ping_sweep_tool.py 192.168.1.0/24 -t 50
   ```

2. **Port Selection**: Use targeted port scanning for faster results
   ```bash
   # Quick web service scan
   python3 main.py 192.168.1.0/24 -p "80,443,8080,8443"
   
   # Common administrative ports
   python3 main.py 192.168.1.0/24 -p "22,23,3389,5900"
   ```

3. **Network Size**: Consider network size when setting expectations
   - /24 network (254 hosts): ~10-30 seconds
   - /16 network (65,534 hosts): Several minutes to hours
   - Use smaller subnets for faster results

## 🛡️ Security Considerations

### Ethical Usage

This tool is designed for legitimate network administration and security testing purposes:

- ✅ **Authorized Networks**: Only scan networks you own or have explicit permission to test
- ✅ **Security Auditing**: Use for authorized penetration testing and security assessments
- ✅ **Network Administration**: Monitor and inventory your own network infrastructure
- ❌ **Unauthorized Scanning**: Do not scan networks without proper authorization

### Legal Compliance

- Always obtain written permission before scanning networks you don't own
- Comply with local laws and regulations regarding network scanning
- Respect terms of service for cloud and hosting providers
- Consider rate limiting in production environments

### Detection Avoidance

The tool generates network traffic that may be detected by:
- Intrusion Detection Systems (IDS)
- Network monitoring tools
- Firewall logs
- Security information and event management (SIEM) systems

## 🐛 Troubleshooting

### Common Issues

**Permission Errors**:
```bash
# Run with appropriate privileges
sudo python3 main.py 192.168.1.0/24
```

**Network Detection Issues**:
```bash
# Manually specify network if auto-detection fails
python3 main.py 192.168.1.0/24
```

**Slow Performance**:
```bash
# Reduce thread count if experiencing timeouts
python3 main.py 192.168.1.0/24 -t 25
```

**Firewall Blocking**:
- Some firewalls may block ICMP (ping) requests
- Port scans may be filtered by host-based firewalls
- Consider using different scanning techniques for hardened networks

### Error Messages

| Error | Solution |
|-------|----------|
| `Invalid network format` | Use proper CIDR notation (e.g., 192.168.1.0/24) |
| `Could not detect local network` | Manually specify the network to scan |
| `Invalid port specification` | Check port format (e.g., "80,443" or "20-25") |
| `Permission denied` | Run with elevated privileges if required |

## 🔄 Examples

### Home Network Audit

```bash
# Discover all devices on home network
python3 main.py 192.168.1.0/24 -o home_network_audit.txt

# Check for common vulnerable services
python3 main.py 192.168.1.0/24 -p "21,22,23,80,135,139,445,3389"
```

### Server Infrastructure Check

```bash
# Quick server health check
python3 main.py 10.0.1.0/24 -p "22,80,443,3306,5432" -q

# Comprehensive server audit
python3 main.py 10.0.1.0/24 -p top100 -o server_audit.txt
```

### IoT Device Discovery

```bash
# Find IoT devices with web interfaces
python3 main.py 192.168.1.0/24 -p "80,443,8080,8443,9000"

# Look for common IoT ports
python3 main.py 192.168.1.0/24 -p "80,443,554,8080,8554,10554"
```

## 📝 Contributing

We welcome contributions! Here's how you can help:

1. **Bug Reports**: Submit detailed bug reports with reproduction steps
2. **Feature Requests**: Suggest new features with use cases
3. **Code Contributions**: Submit pull requests with improvements
4. **Documentation**: Help improve documentation and examples

### Development Setup

```bash
# Clone the repository
git clone https://github.com/1Birdo/NetSweeper.git
cd network-scanner

# Test the tool
python3 main.py --help
```

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks. The authors are not responsible for any misuse or damage caused by this tool.

## 🆘 Support

- **Issues**: Report bugs and request features on GitHub
- **Documentation**: Check this README and inline help (`--help`)
- **Community**: Join discussions in the project's issue tracker

## 📈 Version History

- **v1.0.0**: Initial release with core functionality
  - Multi-threaded ping sweep
  - Port scanning with service detection
  - Basic OS detection
  - Flexible port specification
  - Output formatting options

---

**Happy scanning! 🔍**
