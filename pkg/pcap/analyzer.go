package pcap

import (
	"fmt"
	"sort"
	"time"

	"github.com/AndreHeber/pcap-analyzer/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// Logger interface for outputting information
type Logger interface {
	Info(msg string)
	Error(msg string)
}

// Analysis represents the result of PCAP analysis
type Analysis struct {
	Packets []*SIPPacket
}

// NewAnalysis creates a new analysis instance
func NewAnalysis() *Analysis {
	return &Analysis{
		Packets: make([]*SIPPacket, 0),
	}
}

// AddPacket adds a packet to the analysis
func (a *Analysis) AddPacket(packet *SIPPacket) {
	a.Packets = append(a.Packets, packet)
}

// Analyzer handles PCAP file processing
type Analyzer struct {
	bufferSize int
	logger     Logger
	filters    []PacketFilter
}

// NewAnalyzer creates a new PCAP analyzer
func NewAnalyzer(bufferSize int, logger Logger) *Analyzer {
	return &Analyzer{
		bufferSize: bufferSize,
		logger:     logger,
		filters:    make([]PacketFilter, 0),
	}
}

// AddFilter adds a packet filter to the analyzer
func (a *Analyzer) AddFilter(filter PacketFilter) {
	a.filters = append(a.filters, filter)
}

// matchesFilters checks if a packet matches all configured filters
func (a *Analyzer) matchesFilters(packet *SIPPacket) bool {
	for _, filter := range a.filters {
		if !filter.Match(packet) {
			return false
		}
	}
	return true
}

// AnalyzeFile processes a PCAP file and returns SIP packets
func (a *Analyzer) AnalyzeFile(filename string) (*Analysis, error) {
	// Open PCAP file
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Set BPF filter for SIP traffic (default port 5060)
	err = handle.SetBPFFilter("port 5060")
	if err != nil {
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	analysis := NewAnalysis()

	for packet := range packetSource.Packets() {
		sipPacket, err := a.processSIPPacket(packet)
		if err != nil {
			a.logger.Error(fmt.Sprintf("Error processing packet: %v", err))
			continue
		}

		if sipPacket == nil {
			continue
		}

		// Apply filters
		if !a.matchesFilters(sipPacket) {
			continue
		}

		analysis.AddPacket(sipPacket)
	}

	return analysis, nil
}

// processSIPPacket extracts SIP information from a packet
func (a *Analyzer) processSIPPacket(packet gopacket.Packet) (*SIPPacket, error) {
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil // Not an IPv4 packet
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Get transport layer (TCP/UDP)
	var payload []byte
	var srcPort, dstPort uint16

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		payload = tcp.Payload
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		payload = udp.Payload
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	} else {
		return nil, nil // Not TCP/UDP
	}

	if len(payload) == 0 {
		return nil, nil // No payload
	}

	// Parse SIP message
	sipMsg, err := sip.ParseMessage(payload)
	if err != nil {
		return nil, fmt.Errorf("parsing SIP message: %v", err)
	}

	// Create SIP packet
	sipPacket := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: packet.Metadata().Timestamp,
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  "SIP",
			Length:    uint32(len(payload)),
			Payload:   payload,
		},
		IsRequest:   sipMsg.StartLine.IsRequest,
		Method:      sipMsg.StartLine.Method,
		StatusCode:  sipMsg.StartLine.StatusCode,
		StatusDesc:  sipMsg.StartLine.Reason,
		CallID:      sipMsg.Headers.GetHeader(sip.CallID),
		From:        sipMsg.Headers.GetHeader(sip.From),
		To:          sipMsg.Headers.GetHeader(sip.To),
		CSeq:        sipMsg.Headers.GetHeader(sip.CSeq),
		UserAgent:   sipMsg.Headers.GetHeader(sip.UserAgent),
	}

	return sipPacket, nil
}

// CallGroup represents a group of SIP packets belonging to the same call session
type CallGroup struct {
	CallID  string
	Packets []*SIPPacket
}

// GroupByCall organizes packets by their Call-ID and sorts them chronologically
func (a *Analysis) GroupByCall() map[string]*CallGroup {
	groups := make(map[string]*CallGroup)

	// Group packets by Call-ID
	for _, packet := range a.Packets {
		if packet.CallID == "" {
			continue
		}

		group, exists := groups[packet.CallID]
		if !exists {
			group = &CallGroup{
				CallID:  packet.CallID,
				Packets: make([]*SIPPacket, 0),
			}
			groups[packet.CallID] = group
		}
		group.Packets = append(group.Packets, packet)
	}

	// Sort packets in each group by timestamp
	for _, group := range groups {
		sort.Slice(group.Packets, func(i, j int) bool {
			return group.Packets[i].Timestamp.Before(group.Packets[j].Timestamp)
		})
	}

	return groups
}

// Print outputs the analysis results
func (a *Analysis) Print() {
	fmt.Printf("Found %d SIP packets\n\n", len(a.Packets))

	for _, packet := range a.Packets {
		fmt.Printf("Time: %s\n", packet.Timestamp.Format(time.RFC3339))
		fmt.Printf("From: %s:%d -> %s:%d\n", 
			packet.SrcIP, packet.SrcPort, 
			packet.DstIP, packet.DstPort)
		
		if packet.IsRequest {
			fmt.Printf("Request: %s\n", packet.Method)
		} else {
			fmt.Printf("Response: %d %s\n", packet.StatusCode, packet.StatusDesc)
		}

		fmt.Printf("Call-ID: %s\n", packet.CallID)
		fmt.Printf("From: %s\n", packet.From)
		fmt.Printf("To: %s\n", packet.To)
		fmt.Printf("CSeq: %s\n", packet.CSeq)
		if packet.UserAgent != "" {
			fmt.Printf("User-Agent: %s\n", packet.UserAgent)
		}
		fmt.Println()
	}
}

func parsePort(portStr string) (uint16, error) {
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
} 