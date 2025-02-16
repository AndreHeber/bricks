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
	"github.com/stretchr/testify/mock"
)

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string)  { m.Called(msg) }
func (m *MockLogger) Error(msg string) { m.Called(msg) }

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