package pcap

import (
	"fmt"
	"sort"
	"strings"
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

// Participant represents an endpoint in a SIP call
type Participant struct {
	URI     string
	Address string // IP:Port
}

// CallFlow represents the sequence of SIP interactions in a call
type CallFlow struct {
	CallID       string
	Participants map[string]*Participant // key is the URI
	Interactions []*Interaction
}

// Interaction represents a single SIP message exchange
type Interaction struct {
	Timestamp time.Time
	From      *Participant
	To        *Participant
	Method    string
	Status    string
	IsRequest bool
}

// BuildCallFlow creates a CallFlow from a group of SIP packets
func (g *CallGroup) BuildCallFlow(logger Logger) *CallFlow {
	flow := &CallFlow{
		CallID:       g.CallID,
		Participants: make(map[string]*Participant),
		Interactions: make([]*Interaction, 0, len(g.Packets)),
	}

	// log all packets
	logger.Info(fmt.Sprintf("Processing %d packets for call %s", len(g.Packets), g.CallID))
	for i, packet := range g.Packets {
		// Log each packet's basic info
		if packet.IsRequest {
			logger.Info(fmt.Sprintf("Packet %d: Request %s from %s:%d to %s:%d", 
				i+1, packet.Method, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort))
		} else {
			logger.Info(fmt.Sprintf("Packet %d: Response %d from %s:%d to %s:%d", 
				i+1, packet.StatusCode, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort))
		}
	}

	// Create participants
	for _, packet := range g.Packets {
		fromAddr := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
		toAddr := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
		// fromURI, _ := extractParticipantInfo(packet.From, packet.SrcIP, packet.SrcPort)
		// toURI, _ := extractParticipantInfo(packet.To, packet.DstIP, packet.DstPort)

		if fromAddr != "" {
			if _, ok := flow.Participants[fromAddr]; !ok {
				flow.Participants[fromAddr] = &Participant{Address: fromAddr}
			}
		}
		if toAddr != "" {
			if _, ok := flow.Participants[toAddr]; !ok {
				flow.Participants[toAddr] = &Participant{Address: toAddr}
			}
		}
	}

	// Create interactions
	for _, packet := range g.Packets {
		var from, to *Participant

		// For other flows, use From/To headers
		fromAddr := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
		toAddr := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
		from = flow.Participants[fromAddr]
		to = flow.Participants[toAddr]

		// Create the interaction only if both from and to are valid
		if from != nil && to != nil {
			interaction := &Interaction{
				Timestamp: packet.Timestamp,
				From:      from,
				To:        to,
				Method:    packet.Method,
				IsRequest: packet.IsRequest,
				Status:    fmt.Sprintf("%d %s", packet.StatusCode, packet.StatusDesc),
			}
			flow.Interactions = append(flow.Interactions, interaction)

			// Log the added interaction
			if interaction.IsRequest {
				logger.Info(fmt.Sprintf("Added request interaction: %s->>%s: %s", 
					cleanMermaidName(from.Address),
					cleanMermaidName(to.Address),
					interaction.Method))
			} else {
				logger.Info(fmt.Sprintf("Added response interaction: %s->>%s: %s", 
					cleanMermaidName(from.Address),
					cleanMermaidName(to.Address),
					interaction.Status))
			}
		} else {
			logger.Error(fmt.Sprintf("Missing from (%v) or to (%v) participant for interaction", from, to))
		}
	}

	// Sort interactions by timestamp
	sort.Slice(flow.Interactions, func(i, j int) bool {
		return flow.Interactions[i].Timestamp.Before(flow.Interactions[j].Timestamp)
	})

	// Log all participants
	logger.Info("Final participants:")
	for uri, p := range flow.Participants {
		logger.Info(fmt.Sprintf("  %s at %s", uri, p.Address))
	}

	// Log all interactions in order
	logger.Info("Final interactions (in time order):")
	for i, interaction := range flow.Interactions {
		from := cleanMermaidName(getParticipantName(interaction.From))
		to := cleanMermaidName(getParticipantName(interaction.To))
		if interaction.IsRequest {
			logger.Info(fmt.Sprintf("  %d. %s->>%s: %s", i+1, from, to, interaction.Method))
		} else {
			logger.Info(fmt.Sprintf("  %d. %s->>%s: %s", i+1, from, to, interaction.Status))
		}
	}

	// Log the generated Mermaid diagram
	logger.Info("Generated Mermaid diagram:\n" + flow.GenerateMermaid())

	return flow
}

// extractParticipantInfo extracts URI and address from SIP headers and packet info
func extractParticipantInfo(sipAddr, ip string, port uint16) (uri, addr string) {
	// Extract URI from SIP address (e.g., "Bob <sip:bob@biloxi.com>" -> "sip:bob@biloxi.com")
	if start := strings.Index(sipAddr, "<"); start != -1 {
		if end := strings.Index(sipAddr[start:], ">"); end != -1 {
			uri = sipAddr[start+1 : start+end]
		}
	}
	if uri == "" {
		uri = sipAddr
	}

	// Keep transport parameter in URI
	if strings.Contains(uri, ";transport=") {
		parts := strings.Split(uri, ";")
		baseURI := parts[0]
		for _, part := range parts[1:] {
			if strings.HasPrefix(part, "transport=") {
				uri = baseURI + ";transport=" + strings.ToUpper(strings.TrimPrefix(part, "transport="))
				break
			}
		}
	}

	// Create address string
	if ip != "" {
		addr = fmt.Sprintf("%s:%d", ip, port)
	}
	return uri, addr
}

// GenerateMermaid generates a Mermaid sequence diagram from the call flow
func (f *CallFlow) GenerateMermaid() string {
	var b strings.Builder

	// Start sequence diagram
	b.WriteString("sequenceDiagram\n")
	b.WriteString("    title SIP Call Flow - " + f.CallID + "\n\n")

	// Add participants
	for _, p := range f.Participants {
		// Use URI as participant name, fallback to address if URI is empty
		name := p.URI
		if name == "" {
			name = p.Address
		}
		// Clean up the name for Mermaid
		name = cleanMermaidName(name)
		b.WriteString(fmt.Sprintf("    participant %s\n", name))
	}
	b.WriteString("\n")

	// Add interactions
	for _, interaction := range f.Interactions {
		from := cleanMermaidName(getParticipantName(interaction.From))
		to := cleanMermaidName(getParticipantName(interaction.To))

		if interaction.IsRequest {
			// Request: solid arrow
			b.WriteString(fmt.Sprintf("    %s->>%s: %s\n", from, to, interaction.Method))
		} else {
			// Response: solid arrow with just the status code
			msg := fmt.Sprintf("%s", interaction.Status)
			b.WriteString(fmt.Sprintf("    %s->>%s: %s\n", from, to, msg))
		}
	}

	return b.String()
}

// getParticipantName returns the best name to use for a participant
func getParticipantName(p *Participant) string {
	if p.URI != "" {
		return p.URI
	}
	return p.Address
}

// cleanMermaidName makes a string safe for use in Mermaid diagrams
func cleanMermaidName(s string) string {
	// Replace special characters that could break Mermaid syntax
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "@", "_at_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, ";", "_")
	s = strings.ReplaceAll(s, ",", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "=", "_")
	return s
}

// Print outputs the analysis results
func (a *Analysis) Print() {
	fmt.Printf("Found %d SIP packets\n\n", len(a.Packets))

	for i, packet := range a.Packets {
		fmt.Printf("=== Packet %d ===\n", i+1)
		fmt.Printf("Time: %s\n", packet.Timestamp.Format(time.RFC3339))
		fmt.Printf("Network: %s:%d -> %s:%d\n", 
			packet.SrcIP, packet.SrcPort, 
			packet.DstIP, packet.DstPort)
		
		if packet.IsRequest {
			fmt.Printf("Request: %s\n", packet.Method)
		} else {
			fmt.Printf("Response: %d %s\n", packet.StatusCode, packet.StatusDesc)
		}

		fmt.Printf("Call-ID: %s\n", packet.CallID)
		fmt.Printf("From (raw): %s\n", packet.From)
		fmt.Printf("To (raw): %s\n", packet.To)
		fmt.Printf("CSeq: %s\n", packet.CSeq)
		if packet.UserAgent != "" {
			fmt.Printf("User-Agent: %s\n", packet.UserAgent)
		}

		// Extract and print participant info
		fromURI, _ := extractParticipantInfo(packet.From, "", 0)
		toURI, _ := extractParticipantInfo(packet.To, "", 0)
		fmt.Printf("From URI: %s\n", fromURI)
		fmt.Printf("To URI: %s\n", toURI)

		fmt.Printf("\nRaw payload:\n%s\n", string(packet.Payload))
		fmt.Println()
	}
}

func parsePort(portStr string) (uint16, error) {
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
} 