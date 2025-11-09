 # connection-dump
-A better alternative for tcpdump written in GO. This tools allows tcp and udp traffic monitoring by ports on the network you select and the reporting time you set
A better alternative for tcpdump written in GO. This tool allows TCP and UDP traffic monitoring by ports on the network you select and the reporting time you set.

## Features
- Monitor both TCP and UDP traffic
- Support for multicast traffic
- Cross-platform support (Windows, Mac, Linux)
- Packet logging to file with detailed information
- Verbose output for real-time monitoring
- Configurable reporting intervals

## Installation

### Option 1: Install from Binary Releases
Download the appropriate binary from the [Releases](https://github.com/yourusername/connection-dump/releases) page.

### Option 2: Install from Linux Package Repositories

#### For Debian/Ubuntu systems (.deb packages):
```bash
# Download the latest .deb package
wget https://github.com/yourusername/connection-dump/releases/latest/download/connection-dump_1.0.0_amd64.deb

# Install the package
sudo dpkg -i connection-dump_1.0.0_amd64.deb

# Or use apt to install and handle dependencies
sudo apt install ./connection-dump_1.0.0_amd64.deb
```

#### For RHEL/CentOS/Fedora systems (.rpm packages):
```bash
# Download the latest .rpm package
wget https://github.com/yourusername/connection-dump/releases/latest/download/connection-dump-1.0.0-1.x86_64.rpm

# Install the package
sudo rpm -i connection-dump-1.0.0-1.x86_64.rpm

# Or use yum/dnf to install and handle dependencies
sudo yum install connection-dump-1.0.0-1.x86_64.rpm
# or on newer systems:
sudo dnf install connection-dump-1.0.0-1.x86_64.rpm
```

### Option 3: Build from Source
```bash
go build -o sourceCounter sourceCounter.go
go build -o destinationCounter pkg/destinationCounter.go
```

## Usage

### Source Counter (for Windows)
Captures outgoing packets from your machine.

```bash
sourceCounter [options]
```

Options:
- `-group`: Multicast group IP (default: "239.1.1.1")
- `-iface`: Network interface (default: "en0")
- `-interval`: Reporting interval in seconds (default: 10)
- `-list-ifaces`: List all available pcap interfaces
- `-log`: Log file to write packet details (optional)
- `-proto`: Protocol to capture - "udp", "tcp", or "both" (default: "udp")
- `-v`: Verbose output

Examples:
```bash
# Monitor UDP traffic with verbose output
sourceCounter -proto udp -v

# Monitor both TCP and UDP traffic and log to file
sourceCounter -proto both -log packets.log

# Monitor TCP traffic on specific interface with custom interval
sourceCounter -proto tcp -iface eth0 -interval 5
```

### Destination Counter (for Linux/Mac)
Listens for incoming packets on your machine.

```bash
destinationCounter [options]
```

Options:
- `-group`: Multicast group IP (default: "239.1.1.1")
- `-iface`: Network interface (optional)
- `-t`: Time frame for log report in seconds (default: 30)
- `-log`: Log file to write packet details (optional)
- `-proto`: Protocol to capture - "udp", "tcp", or "both" (default: "udp")
- `-v`: Verbose output

Examples:
```bash
# Monitor UDP traffic with verbose output
destinationCounter -proto udp -v

# Monitor both TCP and UDP traffic and log to file
destinationCounter -proto both -log packets.log

# Monitor TCP traffic with custom reporting interval
destinationCounter -proto tcp -t 15
```

## Configuration
Create a `ports.csv` file in the same directory to specify which ports to monitor:

```
7711,7712,7713,7721,7722,7723
```

## Log File Format
When using the `-log` option, packet details are logged in the following format:
```
[2023-11-09 10:45:30.123] UDP 192.168.1.100:12345 -> 239.1.1.1:7711 Size: 1024 bytes
[2023-11-09 10:45:30.124] TCP 192.168.1.101:54321 -> 239.1.1.1:7712 Size: 512 bytes
```

## Protocol Support
- **UDP**: Supports multicast UDP traffic monitoring
- **TCP**: Supports TCP traffic monitoring (connection-based)
- **Both**: Simultaneously monitors both TCP and UDP traffic on specified ports

## Package Repository Setup

### Setting up APT Repository (Debian/Ubuntu)
For system administrators who want to host their own APT repository:

1. Create a repository structure:
```bash
mkdir -p /var/www/html/connection-dump/deb
cp *.deb /var/www/html/connection-dump/deb/
```

2. Create Packages file:
```bash
cd /var/www/html/connection-dump/deb
dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
```

3. Add to your system's sources:
```bash
echo "deb http://your-repo.com/connection-dump/deb ./" | sudo tee /etc/apt/sources.list.d/connection-dump.list
sudo apt update
sudo apt install connection-dump
```

### Setting up YUM Repository (RHEL/CentOS/Fedora)
For system administrators who want to host their own YUM repository:

1. Create a repository structure:
```bash
mkdir -p /var/www/html/connection-dump/rpm
cp *.rpm /var/www/html/connection-dump/rpm/
createrepo /var/www/html/connection-dump/rpm/
```

2. Create repo file:
```bash
sudo tee /etc/yum.repos.d/connection-dump.repo << EOF
[connection-dump]
name=Connection Dump Repository
baseurl=http://your-repo.com/connection-dump/rpm
enabled=1
gpgcheck=0
EOF
```

3. Install the package:
```bash
sudo yum install connection-dump
# or on newer systems:
sudo dnf install connection-dump
```

## Cross-Platform Notes
- **Windows**: Use `sourceCounter` for capturing outgoing packets
- **Linux/Mac**: Use `destinationCounter` for listening to incoming packets
- Both tools support the same command-line options for consistency
- When installed via package managers, the binaries are available system-wide in `/usr/local/bin/`

## Dependencies
- Go 1.23.5 or later
- github.com/google/gopacket v1.1.19
- golang.org/x/net v0.0.0-20190620200207-3b0461eec859
- golang.org/x/sys v0.0.0-20190412213103-97732733099d

## License
This project is open source. Please refer to the license file for more information.
\ No newline at end of file