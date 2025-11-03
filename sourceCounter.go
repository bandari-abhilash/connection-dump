package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	multicastGroup string
	ifaceName      string
	snapLen        int32         = 1600
	promisc        bool          = false
	timeout        time.Duration = -1
	listIfaces     bool
	reportInterval int
)

func init() {
	flag.BoolVar(&listIfaces, "list-ifaces", false, "List all pcap interfaces")
	flag.StringVar(&multicastGroup, "group", "239.1.1.1", "Multicast group IP")
	flag.StringVar(&ifaceName, "iface", "en0", "Network interface")
	flag.IntVar(&reportInterval, "interval", 10, "Reporting interval in seconds")
	flag.Parse()
}

func main() {
	flag.Parse()
	if listIfaces {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
		}
		for _, device := range devices {
			fmt.Printf("Name: %s\nDescription: %s\n", device.Name, device.Description)
			for _, addr := range device.Addresses {
				fmt.Printf("  IP address: %s\n", addr.IP)
			}
			fmt.Println()
		}
		return
	}

	ports, err := readPortsFromCSV("ports.csv")
	if err != nil {
		log.Fatalf("Failed to read ports from ports.csv: %v", err)
	}
	if len(ports) == 0 {
		log.Fatal("No valid ports specified in ports.csv")
	}

	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	handle, err := pcap.OpenLive(ifaceName, snapLen, promisc, timeout)
	if err != nil {
		log.Fatal("Error opening pcap: ", err)
	}
	defer handle.Close()

	// BPF filter: UDP to multicast group, specific ports, outbound (src not multicast)
	startPort, endPort := ports[0], ports[len(ports)-1]
	filter := fmt.Sprintf("udp and ip dst %s and udp dst portrange %d-%d",
		multicastGroup, startPort, endPort)

	fmt.Printf("Applying BPF filter: %s\n", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v\nFilter was: %s", err, filter)
	}
	fmt.Printf("✓ Capturing on %s for group %s (ports %d-%d)\n",
		ifaceName, multicastGroup, startPort, endPort)

	counters := make(map[int]*int64)
	for _, port := range ports {
		counters[port] = new(int64)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for packet := range packetSource.Packets() {
			countPacket(packet, portSet, counters, multicastGroup)
		}
	}()

	ticker := time.NewTicker(time.Duration(reportInterval) * time.Second)
	defer ticker.Stop()

	fmt.Printf("✓ Monitoring started. Reports every %d seconds (Ctrl+C to stop)\n", reportInterval)
	for range ticker.C {
		logReport("Sender", multicastGroup, counters)
		// wg.Wait() // Graceful, but in practice, run indefinitely
	}
}

func readPortsFromCSV(filename string) ([]int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, nil
	}
	parts := strings.Split(content, ",")
	var ports []int
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %v (%w)", p, err)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func countPacket(packet gopacket.Packet, portSet map[int]bool, counters map[int]*int64, group string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	if !isMulticast(ip.DstIP) || !ip.DstIP.Equal(net.ParseIP(group)) {
		return
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if _, ok := portSet[int(udp.DstPort)]; !ok {
		return
	}

	// Outbound: src is not multicast (local sender)
	if isMulticast(ip.SrcIP) {
		return
	}

	*counters[int(udp.DstPort)]++
}

func isMulticast(ip net.IP) bool {
	return ip.IsMulticast()
}

func logReport(prefix, group string, counters map[int]*int64) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s Report - Group: %s\n", timestamp, prefix, group)
	var total int64
	portStrs := make([]string, 0, len(counters))
	for port, count := range counters {
		portStrs = append(portStrs, fmt.Sprintf("Port %d: %d packets", port, *count))
		total += *count
		*count = 0 // Reset
	}
	fmt.Printf("%s\n", strings.Join(portStrs, " | "))
	fmt.Printf("TOTAL: %d packets/min | AVG: %.1f pkts/port\n\n", total, float64(total)/float64(len(counters)))
}
