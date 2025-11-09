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
)

var (
	multicastGroup string
	ifaceName      string
	timeFrame      int
	protocol       string
	logFile        string
	verbose        bool
)

func init() {
	flag.StringVar(&multicastGroup, "group", "239.1.1.1", "Multicast group IP")
	flag.StringVar(&ifaceName, "iface", "", "Network interface (optional)")
	flag.IntVar(&timeFrame, "t", 30, "Time Frame for log Report")
	flag.StringVar(&protocol, "proto", "udp", "Protocol to capture (udp, tcp, or both)")
	flag.StringVar(&logFile, "log", "", "Log file to write packet details (optional)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()
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

func main() {
	ports, err := readPortsFromCSV("ports.csv")
	if err != nil {
		log.Fatalf("Failed to read ports from ports.csv: %v", err)
	}
	if len(ports) == 0 {
		log.Fatal("No valid ports specified in ports.csv")
	}

	// Initialize log file if specified
	var logWriter *os.File
	var logChan chan string
	if logFile != "" {
		var err error
		logWriter, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer logWriter.Close()
		logChan = make(chan string, 1000)
		go func() {
			for logEntry := range logChan {
				timestamp := time.Now().Format("2006-01-02 15:04:05.000")
				fmt.Fprintf(logWriter, "[%s] %s\n", timestamp, logEntry)
			}
		}()
	}

	var wg sync.WaitGroup
	counters := make(map[int]*int64)

	for _, port := range ports {
		wg.Add(1)
		p := port
		counters[p] = new(int64)

		switch protocol {
		case "udp":
			go listenMulticastUDP(multicastGroup, p, ifaceName, counters[p], &wg, logChan)
		case "tcp":
			go listenMulticastTCP(multicastGroup, p, ifaceName, counters[p], &wg, logChan)
		case "both":
			// Start both UDP and TCP listeners for each port
			wg.Add(1)
			go listenMulticastUDP(multicastGroup, p, ifaceName, counters[p], &wg, logChan)
			go listenMulticastTCP(multicastGroup, p, ifaceName, counters[p], &wg, logChan)
		default:
			log.Fatalf("Invalid protocol: %s. Use 'udp', 'tcp', or 'both'", protocol)
		}
	}

	ticker := time.NewTicker(time.Duration(timeFrame) * time.Second)
	defer ticker.Stop()
	defer wg.Wait()

	if logChan != nil {
		defer close(logChan)
	}

	for range ticker.C {
		logReport("Receiver", multicastGroup, counters)
	}
}

func listenMulticastUDP(group string, port int, ifaceName string, counter *int64, wg *sync.WaitGroup, logChan chan string) {
	defer wg.Done()
	addrStr := fmt.Sprintf("%s:%d", group, port)
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		log.Printf("Error resolving %s: %v", addrStr, err)
		return
	}

	var iface *net.Interface
	if ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("Error getting iface %s: %v", ifaceName, err)
			return
		}
	}

	conn, err := net.ListenMulticastUDP("udp", iface, addr)
	if err != nil {
		log.Printf("Error listening on %s: %v", addrStr, err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error on port %d: %v", port, err)
			continue
		}
		*counter++

		// Log packet details if logging is enabled
		if logChan != nil {
			logEntry := fmt.Sprintf("UDP %s:%d -> %s:%d Size: %d bytes",
				src.IP, src.Port, group, port, n)
			logChan <- logEntry
		}

		if verbose {
			fmt.Printf("[UDP] %s:%d -> %s:%d Size: %d bytes\n",
				src.IP, src.Port, group, port, n)
		}
	}
}

func listenMulticastTCP(group string, port int, ifaceName string, counter *int64, wg *sync.WaitGroup, logChan chan string) {
	defer wg.Done()
	addrStr := fmt.Sprintf("%s:%d", group, port)
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		log.Printf("Error resolving %s: %v", addrStr, err)
		return
	}

	// For TCP, we need to listen and accept connections
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Printf("Error listening on %s: %v", addrStr, err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("Accept error on port %d: %v", port, err)
			continue
		}

		// Handle each connection in a goroutine
		go func(c *net.TCPConn) {
			defer c.Close()
			src := c.RemoteAddr().(*net.TCPAddr)

			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf)
				if err != nil {
					break // Connection closed or error
				}
				*counter++

				// Log packet details if logging is enabled
				if logChan != nil {
					logEntry := fmt.Sprintf("TCP %s:%d -> %s:%d Size: %d bytes",
						src.IP, src.Port, group, port, n)
					logChan <- logEntry
				}

				if verbose {
					fmt.Printf("[TCP] %s:%d -> %s:%d Size: %d bytes\n",
						src.IP, src.Port, group, port, n)
				}
			}
		}(conn)
	}
}

func logReport(prefix, group string, counters map[int]*int64) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s Report - Group: %s\n", timestamp, prefix, group)
	var total int64
	portStrs := make([]string, 0, len(counters))
	for port, count := range counters {
		portStrs = append(portStrs, fmt.Sprintf("Port %d: %d packets", port, *count))
		total += *count
		// Reset for next interval
		*count = 0
	}
	fmt.Printf("%s\n", strings.Join(portStrs, " | "))
	fmt.Printf("TOTAL: %d packets/min | AVG: %.1f pkts/port\n\n", total, float64(total)/float64(len(counters)))
}
