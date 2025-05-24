# Creating the README.md content as a .txt file for download
readme_content = """
# NetSweeper

**NetSweeper** is a fast and lightweight network discovery tool designed for scanning localhost IP ranges. It performs ping sweeps and port scans to identify active hosts and open services within a local network.

## Features

- **Ping Sweep**: Quickly identify live hosts on the network.
- **Port Scanning**: Scan for open ports on discovered hosts.
- **Service Detection**: Identify services running on open ports.
- **Multiple Port Selection Options**:
  - Common ports (default)
  - Top 100 ports
  - All ports (1-65535)
  - Custom port ranges
- **Basic OS Detection**: Infer the operating system of discovered hosts.
- **Threaded Implementation**: Utilize multi-threading for faster scanning.
- **Progress Reporting**: Monitor the scanning progress in real-time.
- **Results Saving**: Save scan results to a file for later analysis.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/1Birdo/NetSweeper.git
   cd NetSweeper
