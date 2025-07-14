# ARP Network Scanner

A professional-grade ARP network scanner for Windows environments. This tool discovers all active devices on your local network by sending ARP requests and mapping IP addresses to MAC addresses.

## 🚀 Features

- **Zero Dependencies**: Works with fresh Python 3 installations
- **Windows Optimized**: Native Windows command integration
- **Professional Output**: Clean, formatted results with timestamps
- **Multiple Formats**: TXT and JSON output options
- **Auto-Detection**: Automatically discovers your network range
- **Rescan Capability**: Option to rescan without restarting
- **Admin Integration**: Works seamlessly with `arp -d` workflows
- **Progress Tracking**: Real-time scan progress indicators

## 📋 Requirements

- Windows 10/11
- Python 3.6 or higher
- Administrator privileges (for ARP cache clearing)

## 🎯 Quick Start

### Basic Usage
```bash
# Auto-detect network and scan
python arp_scanner.py

# Scan specific network
python arp_scanner.py -n 192.168.1.0/24
```

### Professional Workflow
```bash
# Step 1: Clear ARP cache (as Administrator)
arp -d

# Step 2: Run comprehensive scan
python arp_scanner.py -n 192.168.1.0/24 -o daily_scan -f both

# Step 3: Review results and rescan if needed
```

## 📖 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-n, --network` | Network to scan (CIDR notation) | `-n 192.168.1.0/24` |
| `-c, --clear` | Clear ARP cache before scanning | `-c` |
| `-o, --output` | Output filename (without extension) | `-o network_scan` |
| `-f, --format` | Output format: txt, json, or both | `-f both` |
| `-q, --quiet` | Quiet mode (minimal output) | `-q` |
| `-h, --help` | Show help message | `-h` |

## 💡 Usage Examples

### Daily Network Audit
```bash
python arp_scanner.py -c -n 192.168.1.0/24 -o daily_audit -f both
```

### Quick Network Check
```bash
python arp_scanner.py
```
*Auto-detects network and provides interactive scanning*

### Automated Monitoring
```bash
python arp_scanner.py -q -n 192.168.1.0/24 -o automated_scan -f json
```

### Multiple Subnet Scanning
```bash
python arp_scanner.py -n 192.168.1.0/24 -o subnet1
python arp_scanner.py -n 192.168.2.0/24 -o subnet2
python arp_scanner.py -n 10.0.0.0/24 -o subnet3
```

## 📊 Output Formats

### Console Output
```
[*] Scanning network: 192.168.1.0/24
[*] Total IPs to scan: 254
[*] Sending ARP requests...

[+] Found 5 active devices:
------------------------------------------------------------
IP Address      MAC Address        Status
------------------------------------------------------------
192.168.1.1     AA-BB-CC-DD-EE-FF  EXISTING
192.168.1.50    11-22-33-44-55-66  NEW
192.168.1.100   77-88-99-AA-BB-CC  NEW
192.168.1.150   DD-EE-FF-11-22-33  NEW
192.168.1.200   44-55-66-77-88-99  EXISTING
```

### TXT Output Format
```
ARP Network Scan Results
Scan Time: 20250715_143022
Total Devices: 5
----------------------------------------
192.168.1.1:AA-BB-CC-DD-EE-FF
192.168.1.50:11-22-33-44-55-66
192.168.1.100:77-88-99-AA-BB-CC
192.168.1.150:DD-EE-FF-11-22-33
192.168.1.200:44-55-66-77-88-99
```

### JSON Output Format
```json
{
  "scan_time": "20250715_143022",
  "total_devices": 5,
  "devices": {
    "192.168.1.1": "AA-BB-CC-DD-EE-FF",
    "192.168.1.50": "11-22-33-44-55-66",
    "192.168.1.100": "77-88-99-AA-BB-CC",
    "192.168.1.150": "DD-EE-FF-11-22-33",
    "192.168.1.200": "44-55-66-77-88-99"
  }
}
```

## 🔧 How It Works

1. **Network Discovery**: Automatically detects your local network or uses specified CIDR
2. **ARP Requests**: Sends ping to each IP in range to trigger ARP entries
3. **Table Parsing**: Reads Windows ARP table (`arp -a`) and extracts IP:MAC pairs
4. **Results Processing**: Filters and formats discovered devices
5. **Output Generation**: Displays results and saves to specified formats

### Technical Details
- Uses Windows native `ping` and `arp` commands
- Concurrent IP pinging for faster scanning
- Smart ARP table parsing with regex filtering
- Automatic broadcast/multicast address filtering
- Progress tracking and status indicators

## 🛡️ Security & Best Practices

### Administrator Privileges
- **ARP cache clearing** requires Administrator privileges
- **Network scanning** works with standard user privileges
- **Recommendation**: Run Command Prompt as Administrator

### Network Considerations
- **Same subnet only**: ARP works within broadcast domain
- **Firewall impact**: Some devices may block ping but still appear in ARP table
- **Network load**: Scanning large networks generates network traffic

### Usage Guidelines
```bash
# Best practice workflow
1. Open Command Prompt as Administrator
2. Clear ARP cache: arp -d
3. Run scanner: python arp_scanner.py -n YOUR_NETWORK/24 -o results
4. Review results and save for documentation
5. Rescan if needed using the interactive prompt
```

## 🚨 Troubleshooting

### Common Issues

#### "No devices found"
**Cause**: Insufficient privileges or network connectivity issues
**Solution**: 
- Run as Administrator
- Check network connectivity
- Verify network range is correct

#### "Invalid network format"
**Cause**: Incorrect CIDR notation
**Solution**: Use proper format like `192.168.1.0/24`, not `192.168.1.*`

#### "Failed to clear ARP cache"
**Cause**: Not running as Administrator
**Solution**: 
- Run Command Prompt as Administrator
- Or skip the `-c` flag and manually run `arp -d`

#### Missing devices in results
**Cause**: Devices with strict firewall blocking ping
**Solution**: 
- These devices won't respond to ping but may have existing ARP entries
- Try scanning without clearing ARP cache first

### Network Range Examples
```bash
# Common network ranges
192.168.1.0/24   # 192.168.1.1 to 192.168.1.254
192.168.0.0/16   # 192.168.0.1 to 192.168.255.254
10.0.0.0/24      # 10.0.0.1 to 10.0.0.254
172.16.0.0/20    # 172.16.0.1 to 172.16.15.254
```

## 📝 Automation & Batch Files

### Daily Monitoring Script
Create `daily_scan.bat`:
```batch
@echo off
echo ARP Network Scanner - Daily Monitoring
echo =====================================
echo.
echo Clearing ARP cache...
arp -d
echo.
echo Running network scan...
python arp_scanner.py -n 192.168.1.0/24 -o daily_scan_%date:~-4,4%%date:~-10,2%%date:~-7,2% -f both
echo.
echo Scan complete! Check the generated files.
pause
```

### Scheduled Task Integration
```bash
# For Windows Task Scheduler
python.exe "C:\path\to\arp_scanner.py" -q -n 192.168.1.0/24 -o scheduled_scan -f json
```

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests. This tool is designed for professional network administration and security auditing.

## 📄 License

This project is open source and available under the MIT License.

## 🔗 Additional Resources

- [ARP Protocol Documentation](https://tools.ietf.org/html/rfc826)
- [Windows ARP Command Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/arp)
- [CIDR Notation Guide](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review command line options with `-h`
3. Ensure you're running with appropriate privileges
4. Verify network connectivity and range settings

---
