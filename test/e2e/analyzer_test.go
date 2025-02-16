package e2e

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndreHeber/pcap-analyzer/pkg/pcap"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestLogger struct {
	t *testing.T
}

func (l *TestLogger) Info(msg string)  { l.t.Log(msg) }
func (l *TestLogger) Error(msg string) { l.t.Log(msg) }

func TestPcapAnalysis(t *testing.T) {
	// Create a temporary test pcap file
	testPcap := filepath.Join(t.TempDir(), "test.pcap")
	err := createTestPcap(testPcap)
	require.NoError(t, err)
	defer os.Remove(testPcap)

	logger := &TestLogger{t: t}
	analyzer := pcap.NewAnalyzer(100, logger)

	analysis, err := analyzer.AnalyzeFile(testPcap)
	require.NoError(t, err)

	// Verify analysis results
	assert.NotZero(t, analysis.PacketCount)
	assert.False(t, analysis.FirstPacketTime.IsZero())
	assert.False(t, analysis.LastPacketTime.IsZero())
	assert.NotEmpty(t, analysis.UniqueIPs)
	assert.NotEmpty(t, analysis.UniquePorts)
	assert.NotEmpty(t, analysis.Flows)

	// Verify time ordering
	assert.True(t, analysis.FirstPacketTime.Before(analysis.LastPacketTime))
}

func createTestPcap(filepath string) error {
	// Create a pcap file with a test packet
	handle, err := pcap.OpenLive("lo", 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("creating pcap handle: %w", err)
	}
	defer handle.Close()

	// Create a dummy packet
	eth := layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
	}
	ip := layers.IPv4{
		SrcIP: net.IP{192, 168, 1, 1},
		DstIP: net.IP{192, 168, 1, 2},
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts, &eth, &ip, &tcp)
	if err != nil {
		return fmt.Errorf("serializing packet: %w", err)
	}

	// Write to file
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("writing pcap header: %w", err)
	}

	err = w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}, buffer.Bytes())
	if err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}

	return nil
} 