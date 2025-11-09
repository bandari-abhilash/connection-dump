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
```bash
go build -o sourceCounter sourceCounter.go
go build -o destinationCounter pkg/destinationCounter.go
```

## Usage

### Source Counter (for Windows)
Captures outgoing packets from your machine.

```bash
./sourceCounter [options]
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
./sourceCounter -proto udp -v

# Monitor both TCP and UDP traffic and log to file
./sourceCounter -proto both -log packets.log

# Monitor TCP traffic on specific interface with custom interval
./sourceCounter -proto tcp -iface eth0 -interval 5
```

### Destination Counter (for Linux/Mac)
Listens for incoming packets on your machine.

```bash
./destinationCounter [options]
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
./destinationCounter -proto udp -v

# Monitor both TCP and UDP traffic and log to file
./destinationCounter -proto both -log packets.log

# Monitor TCP traffic with custom reporting interval
./destinationCounter -proto tcp -t 15
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

## Cross-Platform Notes
- **Windows**: Use `sourceCounter.go` for capturing outgoing packets
- **Linux/Mac**: Use `pkg/destinationCounter.go` for listening to incoming packets
- Both tools support the same command-line options for consistency

## Dependencies
- Go 1.23.5 or later
- github.com/google/gopacket v1.1.19
- golang.org/x/net v0.0.0-20190620200207-3b0461eec859
- golang.org/x/sys v0.0.0-20190412213103-97732733099d

## License
This project is open source. Please refer to the license file for more information.
\ No newline at end of file