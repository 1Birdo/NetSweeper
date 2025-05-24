# Local Network Scanner 🔍

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey)

A powerful, lightweight network scanning tool designed for local network reconnaissance. This Python-based scanner provides NMAP-like functionality with an emphasis on simplicity and speed for local network environments.

## Features ✨

- **Ping Sweep**: Rapidly discover live hosts on your local network
- **Port Scanning**: Comprehensive port scanning with service detection
- **Multiple Scan Modes**:
  - Common ports (22, 80, 443, etc.)
  - Top 100 most used ports
  - Full port range (1-65535)
  - Custom port specifications
- **OS Fingerprinting**: Basic OS detection via TTL and port analysis
- **Performance Optimized**:
  - Multi-threaded architecture
  - Configurable thread pool
  - Progress indicators
- **Output Options**:
  - Console display
  - File export
  - Quiet mode for scripting

## Installation 🛠️

### Prerequisites
- Python 3.6 or higher
- Administrator/root privileges recommended for full functionality

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/local-network-scanner.git
cd local-network-scanner

# Run the scanner (auto-detects local network)
python scanner.py

# Using pipx (recommended for isolated installation)
pipx install git+https://github.com/yourusername/local-network-scanner.git

# Traditional pip installation
pip install git+https://github.com/yourusername/local-network-scanner.git
