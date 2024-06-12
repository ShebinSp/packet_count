package main

import (
	"C"
)
import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf xdp.c

// Placeholder for the server struct with Submit method.
type Server struct{}

// Submit method for the server struct.
func (s *Server) Submit(m PacketCounts) {
    // Submit packet counts to server or process them.
}

// Declare excludeIPs and initialize it.
var excludeIPs = map[string]bool{
    "192.168.1.1": true,
    "10.0.0.1":    true,
}

// Declare srv as an instance of Server.
var srv = &Server{}

// Define a flag to specify the network interface to attach the XDP program to
var (
	ifaceName = flag.String("iface", "", "network interface to attach XDP program to")
)

/*
We will use a utility function, parsePacketCounts, to read the map contents and parse the packet counts. This function will
read the map contents in a loop.As we will be given raw bytes from the map, we will need to parse the bytes and convert them
into a human-readable format. We will define a new type PacketCounts to store the parsed map contents.
*/

// IPMetadata represents metadata for IP packets, including source IP, source port, and destination port.
type IPMetadata struct {
	SrcIP   netip.Addr // Source IP address
	SrcPort uint16     // Source port number
	DstPort uint16     // Destination port number
}

// UnmarshalBinary parses a byte slice into an IPMetadata struct.
func (t *IPMetadata) UnmarshalBinary(data []byte) (err error) {
	// Check if the data length is exactly 8 bytes.
	if len(data) != 8 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}

	// Unmarshal the source IP address from the last 4 bytes of the data.
	if err = t.SrcIP.UnmarshalBinary(data[4:8]); err != nil {
		return
	}

	// Unmarshal the source port from bytes 2 and 3 (big-endian order).
	t.SrcPort = uint16(data[3])<<8 | uint16(data[2])

	// Unmarshal the destination port from bytes 0 and 1 (big-endian order).
	t.DstPort = uint16(data[1])<<8 | uint16(data[0])

	return nil
}

// String returns a string representation of the IPMetadata in the format "SrcIP:SrcPort => :DstPort".
func (t IPMetadata) String() string {
	return fmt.Sprintf("%s:%d => :%d", t.SrcIP, t.SrcPort, t.DstPort)
}

// PacketCounts is a map that associates a string key (IPMetadata) with an integer value (packet count).
type PacketCounts map[string]int

// String returns a formatted string representation of the PacketCounts map.
func (i PacketCounts) String() string {
	var keys []string

	// Collect all the keys from the map.
	for k := range i {
		keys = append(keys, k)
	}

	// Sort the keys alphabetically.
	sort.Strings(keys)

	var sb strings.Builder

	// Build the formatted string with each key and its corresponding value.
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("%s\t| %d\n", k, i[k]))
	}
	return sb.String()
}


// parsePacketCounts parses packet counts from an eBPF map, excluding packets from specific IPs.
func parsePacketCounts(m *ebpf.Map, excludeIps map[string]bool) (PacketCounts, error) {
	var (
		key    IPMetadata           // Variable to hold the current map key (IP metadata)
		val    uint32               // Variable ot hold the current map value (packet count)
		counts = make(PacketCounts) // Initialize an empty map t store the packet counts.
	)

	// Create an iterator to traverse the eBPF map.
	iter := m.Iterate()

	// Iterate over all key-value parits in the eBPF map.
	for iter.Next(&key, &val) {
		// Check if the source IP of the current key is in the exclude list.
		if _, ok := excludeIps[key.SrcIP.String()]; ok {
			// If the source IP is in the exclude list, skip this key-value pair.
			continue
		}

		// Convert the key to a string and store the packet count in the counts map.
		counts[key.String()] = int(val)
	}

	// Return the populated counts map and any error encountered during iteration.
	return counts, iter.Err()
}


func main() {
	// Set the log prefix and flags for better log output format
	log.SetPrefix("packet_count: ")
	log.SetFlags(log.Ltime | log.Lshortfile)
	flag.Parse() // Parse the command line flag

	// Create a channel to receive OS signals for terminating the program
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Look up the network interface by name.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("network iface lookup for %q: %s", *ifaceName, err)
	}

	// Load pre-compiled programs and maps into the kernal
	objs := ebpfObjects{}

	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	// Ensure the eBPF objects are closed on program exit.
	defer objs.Close()

	// Attach the XDP program to the network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %v", err)
	}
	// Ensure the link is closed on program exit.
	defer l.Close()
	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

	// Create a ticker that ticks every second
	ticker := time.NewTicker(time.Second)
	// Ensure the ticker is closed on progtam exit.
	defer ticker.Stop()

	for {
		select {
		case <-stop: // Handle program termination signal
			if err := objs.XdpStatsMap.Close(); err != nil {
				log.Fatalf("closing map reader: %s", err)
			}
			return

		case <-ticker.C: // Handle ticker tick event.
		// Parse packet counts from the eBPF map.
			m, err := parsePacketCounts(objs.XdpStatsMap, excludeIPs)
			if err != nil {
				log.Printf("Error reading map: %s", err)
				continue
			}
			log.Printf("Map contents: \n%s", m)
			// Submit the parsed packet counts to a server or other processing function.
			srv.Submit(m)
		}
	}
}

