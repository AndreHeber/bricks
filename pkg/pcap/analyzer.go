package pcap

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Flow represents a network flow between two endpoints
type Packet struct {
	Source      string
	Destination string
	Timestamp   time.Time
	SIPPayload  []byte
	SDPPayload  []byte
	Protocol    string
	SIPMethod   string
	SIPHeaders  map[string]string
	SDPBody     string
}

// Analysis contains the results of a pcap analysis
type Analysis struct {
	FirstPacketTime time.Time
	LastPacketTime  time.Time
	PacketCount     int
	UniqueAddresses map[string]struct{}
	Packets         []Packet
}

// Logger interface for dependency injection of logging
type Logger interface {
	Info(msg string)
	Error(msg string)
}

// Analyzer handles pcap file analysis
type Analyzer struct {
	maxPackets int
	logger     Logger
	filters    []PacketFilter
}

// NewAnalyzer creates a new pcap analyzer
func NewAnalyzer(maxPackets int, logger Logger) *Analyzer {
	return &Analyzer{
		maxPackets: maxPackets,
		logger:     logger,
		filters:    make([]PacketFilter, 0),
	}
}

// AddFilter adds a packet filter to the analyzer
func (a *Analyzer) AddFilter(filter PacketFilter) {
	a.filters = append(a.filters, filter)
}

// AnalyzeFile analyzes a pcap file and returns the analysis results
func (a *Analyzer) AnalyzeFile(filepath string) (*Analysis, error) {
	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening pcap file: %w", err)
	}
	defer handle.Close()

	// Set BPF filter for SIP traffic (default port 5060)
	err = handle.SetBPFFilter("port 5060")
	if err != nil {
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}

	analysis := &Analysis{
		UniqueAddresses: make(map[string]struct{}),
		Packets:         make([]Packet, 0),
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if err := a.processPacket(packet, analysis); err != nil {
			a.logger.Error(fmt.Sprintf("processing packet: %v", err))
			continue
		}

		analysis.PacketCount++
		if analysis.PacketCount >= a.maxPackets {
			a.logger.Info(fmt.Sprintf("Reached maximum packet count of %d", a.maxPackets))
			break
		}
	}

	return analysis, nil
}

// parseSIPPacket parses SIP packet content
func parseSIPPacket(payload []byte) (string, map[string]string, string) {
	content := string(payload)
	lines := strings.Split(content, "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(content, "\n")
	}

	if len(lines) == 0 {
		return "", nil, ""
	}

	// Parse first line for method
	method := ""
	if strings.HasPrefix(lines[0], "SIP/") {
		// SIP/2.0 200 OK
		responseCode := strings.Split(lines[0], " ")[1:]
		// This is a response
		method = "Response: " + strings.Join(responseCode, " ")
	} else {
		// This is a request
		parts := strings.Split(lines[0], " ")
		if len(parts) > 0 {
			method = "Request: " + parts[0]
		}
	}

	// Parse headers
	headers := make(map[string]string)
	var sdpContent strings.Builder
	isSDPContent := false

	for _, line := range lines[1:] {
		if line == "" {
			isSDPContent = true
			continue
		}

		if isSDPContent {
			sdpContent.WriteString(line)
			sdpContent.WriteString("\r\n")
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	return method, headers, sdpContent.String()
}

func (a *Analyzer) processPacket(packet gopacket.Packet, analysis *Analysis) error {
	timestamp := packet.Metadata().Timestamp

	// Record first and last packet times
	if analysis.FirstPacketTime.IsZero() {
		analysis.FirstPacketTime = timestamp
	}
	analysis.LastPacketTime = timestamp

	// Extract IP and port information
	ipLayer := packet.NetworkLayer()
	tcpLayer := packet.TransportLayer()

	if ipLayer == nil || tcpLayer == nil {
		return fmt.Errorf("packet missing IP or transport layer")
	}

	srcIP := ipLayer.NetworkFlow().Src().String()
	dstIP := ipLayer.NetworkFlow().Dst().String()
	srcPort := tcpLayer.TransportFlow().Src().String()
	dstPort := tcpLayer.TransportFlow().Dst().String()

	// Record unique addresses
	srcAddr := fmt.Sprintf("%s:%s", srcIP, srcPort)
	dstAddr := fmt.Sprintf("%s:%s", dstIP, dstPort)
	analysis.UniqueAddresses[srcAddr] = struct{}{}
	analysis.UniqueAddresses[dstAddr] = struct{}{}

	// Get payload from different layers
	var sipPayload []byte
	var sdpPayload []byte
	var protocol string
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		sipPayload = appLayer.LayerContents()
		sdpPayload = appLayer.Payload()
		protocol = "SIP" // Assume SIP for port 5060/5080
	}

	// Parse SIP content if present
	var sipMethod string
	var sipHeaders map[string]string
	var sdpBody string
	if protocol == "SIP" && sipPayload != nil {
		sipMethod, sipHeaders, _ = parseSIPPacket(sipPayload)
		sdpBody = string(sdpPayload)
	}

	// Record packet information
	analysis.Packets = append(analysis.Packets, Packet{
		Source:      srcAddr,
		Destination: dstAddr,
		Timestamp:   timestamp,
		SIPPayload:  sipPayload,
		SDPPayload:  sdpPayload,
		Protocol:    protocol,
		SIPMethod:   sipMethod,
		SIPHeaders:  sipHeaders,
		SDPBody:     sdpBody,
	})

	return nil
}

func parsePort(portStr string) (uint16, error) {
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
}

// Print formats and prints the analysis results
func (a *Analysis) Print() {
	fmt.Println("\nCapture Period:")
	fmt.Printf("Start: %s\n", a.FirstPacketTime.Format(time.RFC3339))
	fmt.Printf("End:   %s\n", a.LastPacketTime.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", a.LastPacketTime.Sub(a.FirstPacketTime))

	fmt.Println("\nUnique Addresses:")
	for addr := range a.UniqueAddresses {
		fmt.Printf("- %s\n", addr)
	}

	fmt.Println("\nPacket Details:")
	for _, pkt := range a.Packets {
		fmt.Printf("Time: %s\n", pkt.Timestamp.Format(time.RFC3339))
		fmt.Printf("Source: %s\n", pkt.Source)
		fmt.Printf("Destination: %s\n", pkt.Destination)
		if pkt.Protocol == "SIP" {
			fmt.Println("SIP Packet:")
			fmt.Printf("  Method: %s\n", pkt.SIPMethod)
			if len(pkt.SIPHeaders) > 0 {
				fmt.Println("  Headers:")
				for key, value := range pkt.SIPHeaders {
					fmt.Printf("    %s: %s\n", key, value)
				}
			}
			if pkt.SDPBody != "" {
				fmt.Println("  SDP Body:")
				lines := strings.Split(pkt.SDPBody, "\r\n")
				for _, line := range lines {
					fmt.Printf("    %s\n", line)
				}
			}
		} else if pkt.SIPPayload != nil {
			fmt.Printf("Payload (%d bytes):\n", len(pkt.SIPPayload))
			fmt.Printf("  Hex: %x\n", pkt.SIPPayload)
			fmt.Printf("  ASCII: %s\n", string(pkt.SIPPayload))
		}
		fmt.Println()
	}
} 