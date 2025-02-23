package pcap

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	infoMsgs  []string
	errorMsgs []string
}

func (m *MockLogger) Info(msg string)  { m.infoMsgs = append(m.infoMsgs, msg) }
func (m *MockLogger) Error(msg string) { m.errorMsgs = append(m.errorMsgs, msg) }

// MockFilter implements the PacketFilter interface for testing
type MockFilter struct {
	shouldMatch bool
}

func (f *MockFilter) Match(packet *SIPPacket) bool {
	return f.shouldMatch
}

func TestProcessPacket(t *testing.T) {
	tests := []struct {
		name           string
		packet         gopacket.Packet
		expectedError  bool
		expectedPackets int
		expectedAddrs  int
		setupMockLayer bool
	}{
		{
			name:           "Valid packet",
			setupMockLayer: true,
			expectedPackets: 1,
			expectedAddrs:  2,
		},
		{
			name:           "Invalid packet without layers",
			setupMockLayer: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			analyzer := NewAnalyzer(100, logger)
			analysis := &Analysis{
				UniqueAddresses: make(map[string]struct{}),
				Packets:         make([]Packet, 0),
			}

			var packet gopacket.Packet
			if tt.setupMockLayer {
				packet = createMockPacket()
			} else {
				packet = gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
			}

			err := analyzer.processPacket(packet, analysis)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, analysis.Packets, tt.expectedPackets)
				assert.Len(t, analysis.UniqueAddresses, tt.expectedAddrs)
			}
		})
	}
}

func createMockPacket() gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 2},
	}

	payload := []byte("Test TCP Payload")

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
	}

	// Compute TCP checksum
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:      true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		eth,
		ip,
		tcp,
		gopacket.Payload(payload),
	)
	if err != nil {
		panic(fmt.Sprintf("Error creating packet: %v", err))
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    uint16
		expectError bool
	}{
		{
			name:     "Valid port",
			input:    "80",
			expected: 80,
		},
		{
			name:        "Invalid port",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "Empty port",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePort(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseSIPPacket(t *testing.T) {
	payload := []byte(`INVITE sip:user@example.com SIP/2.0
Via: SIP/2.0/UDP pc33.example.com
To: sip:user@example.com
From: sip:caller@example.com
Call-ID: a84b4c76e66710

v=0
o=user1 53655765 2353687637 IN IP4 pc33.example.com
s=Session SDP
c=IN IP4 pc33.example.com
t=0 0
m=audio 3456 RTP/AVP 0
`)

	method, headers, sdp := parseSIPPacket(payload)

	assert.Equal(t, "Request: INVITE", method)
	assert.Equal(t, "sip:user@example.com", headers["To"])
	assert.Contains(t, sdp, "v=0")
	assert.Contains(t, sdp, "m=audio")
}

func TestAnalysis_Print(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create test analysis
	analysis := &Analysis{
		FirstPacketTime: time.Date(2024, 3, 19, 10, 0, 0, 0, time.UTC),
		LastPacketTime:  time.Date(2024, 3, 19, 10, 0, 1, 0, time.UTC),
		PacketCount:     2,
		UniqueAddresses: map[string]struct{}{
			"192.168.1.1:5060": {},
			"192.168.1.2:5060": {},
		},
		Packets: []Packet{
			{
				Source:      "192.168.1.1:5060",
				Destination: "192.168.1.2:5060",
				Timestamp:   time.Date(2024, 3, 19, 10, 0, 0, 0, time.UTC),
				Protocol:    "SIP",
				SIPMethod:   "Request: INVITE",
				SIPHeaders: map[string]string{
					"Via":     "SIP/2.0/UDP pc33.example.com",
					"To":      "sip:user@example.com",
					"From":    "sip:caller@example.com",
					"Call-ID": "a84b4c76e66710",
				},
				SDPBody: "v=0\r\no=user1 53655765 2353687637 IN IP4 pc33.example.com\r\ns=Session SDP\r\n",
			},
			{
				Source:      "192.168.1.2:5060",
				Destination: "192.168.1.1:5060",
				Timestamp:   time.Date(2024, 3, 19, 10, 0, 1, 0, time.UTC),
				Protocol:    "SIP",
				SIPMethod:   "Response: 200 OK",
				SIPHeaders: map[string]string{
					"Via":     "SIP/2.0/UDP pc33.example.com",
					"To":      "sip:user@example.com",
					"From":    "sip:caller@example.com",
					"Call-ID": "a84b4c76e66710",
				},
			},
		},
	}

	// Print analysis
	analysis.Print()

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected information
	expectedStrings := []string{
		"Capture Period:",
		"Start: 2024-03-19T10:00:00Z",
		"End:   2024-03-19T10:00:01Z",
		"Duration: 1s",
		"Unique Addresses:",
		"192.168.1.1:5060",
		"192.168.1.2:5060",
		"Packet Details:",
		"Request: INVITE",
		"Response: 200 OK",
		"Via: SIP/2.0/UDP pc33.example.com",
		"To: sip:user@example.com",
		"From: sip:caller@example.com",
		"Call-ID: a84b4c76e66710",
		"SDP Body:",
		"v=0",
		"o=user1 53655765 2353687637 IN IP4 pc33.example.com",
		"s=Session SDP",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Output should contain %q", expected)
	}
}

func TestAnalyzer_AddFilter(t *testing.T) {
	logger := &MockLogger{}
	analyzer := NewAnalyzer(100, logger)

	filter1 := &MockFilter{shouldMatch: true}
	filter2 := &MockFilter{shouldMatch: false}

	analyzer.AddFilter(filter1)
	analyzer.AddFilter(filter2)

	if len(analyzer.filters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(analyzer.filters))
	}
}

func TestAnalyzer_MatchesFilters(t *testing.T) {
	logger := &MockLogger{}
	analyzer := NewAnalyzer(100, logger)

	packet := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
		},
		Method: "INVITE",
	}

	// Test with no filters
	if !analyzer.matchesFilters(packet) {
		t.Error("Expected packet to match with no filters")
	}

	// Test with matching filter
	analyzer.AddFilter(&MockFilter{shouldMatch: true})
	if !analyzer.matchesFilters(packet) {
		t.Error("Expected packet to match with true filter")
	}

	// Test with non-matching filter
	analyzer.AddFilter(&MockFilter{shouldMatch: false})
	if analyzer.matchesFilters(packet) {
		t.Error("Expected packet to not match with false filter")
	}
}

func TestAnalyzer_ProcessSIPPacket(t *testing.T) {
	logger := &MockLogger{}
	analyzer := NewAnalyzer(100, logger)

	// Create a mock packet with SIP payload
	payload := []byte("INVITE sip:bob@biloxi.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n" +
		"To: Bob <sip:bob@biloxi.com>\r\n" +
		"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n")

	// Create IP layer
	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{192, 168, 1, 2},
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5060),
		DstPort: layers.UDPPort(5060),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Create packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		udp,
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	
	// Process the packet
	sipPacket, err := analyzer.processSIPPacket(packet)
	if err != nil {
		t.Fatalf("Failed to process SIP packet: %v", err)
	}

	// Verify the processed packet
	if sipPacket == nil {
		t.Fatal("Expected non-nil SIP packet")
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"SrcIP", sipPacket.SrcIP, "192.168.1.1"},
		{"DstIP", sipPacket.DstIP, "192.168.1.2"},
		{"SrcPort", sipPacket.SrcPort, uint16(5060)},
		{"DstPort", sipPacket.DstPort, uint16(5060)},
		{"Protocol", sipPacket.Protocol, "SIP"},
		{"Method", sipPacket.Method, "INVITE"},
		{"IsRequest", sipPacket.IsRequest, true},
		{"CallID", sipPacket.CallID, "a84b4c76e66710@pc33.atlanta.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v; want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestAnalysis_AddPacket(t *testing.T) {
	analysis := NewAnalysis()
	
	packet := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
		},
		Method: "INVITE",
	}

	analysis.AddPacket(packet)

	if len(analysis.Packets) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(analysis.Packets))
	}

	if analysis.Packets[0] != packet {
		t.Error("Stored packet does not match input packet")
	}
} 