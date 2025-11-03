package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	multicastGroup string
	portRange      string
	ifaceName      string
	timeFrame      int
)

func init() {
	flag.StringVar(&multicastGroup, "group", "239.1.1.1", "Multicast group IP")
	flag.StringVar(&portRange, "ports", "7711-7723", "Port range (e.g., 10000-10019)")
	flag.StringVar(&ifaceName, "iface", "", "Network interface (optional)")
	flag.IntVar(&timeFrame, "t", 30, "Time Frame for log Report")
	flag.Parse()
}

func main() {
	ports := parsePortRange(portRange)
	if len(ports) == 0 {
		log.Fatal("Invalid port range")
	}

	var wg sync.WaitGroup
	counters := make(map[int]*int64)
	for _, port := range ports {
		wg.Add(1)
		p := port
		counters[p] = new(int64)
		go listenMulticast(multicastGroup, p, ifaceName, counters[p], &wg)
	}

	ticker := time.NewTicker(time.Duration(timeFrame) * time.Second)
	defer ticker.Stop()
	defer wg.Wait()

	for range ticker.C {
		logReport("Receiver", multicastGroup, counters)
	}
}

func parsePortRange(rangeStr string) []int {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		log.Fatal("Port range must be start-end")
	}
	start, _ := strconv.Atoi(parts[0])
	end, _ := strconv.Atoi(parts[1])
	var ports []int
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports
}

func listenMulticast(group string, port int, ifaceName string, counter *int64, wg *sync.WaitGroup) {
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
		_, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error on port %d: %v", port, err)
			continue
		}
		*counter++
		// Optional: log individual packets if verbose
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
	fmt.Printf("%s | Total: %d packets\n", strings.Join(portStrs, " | "), total)
}
