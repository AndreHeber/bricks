package e2e

import (
	"testing"

	"github.com/AndreHeber/pcap-analyzer/pkg/pcap"
	"github.com/stretchr/testify/assert"
)

type testLogger struct{}

func (l *testLogger) Info(msg string)  {}
func (l *testLogger) Error(msg string) {}

func TestAnalyzer_E2E(t *testing.T) {
	logger := &testLogger{}
	analyzer := pcap.NewAnalyzer(100, logger)

	t.Run("REGISTER-Request.pcap", func(t *testing.T) {
		// Test file analysis
		analysis, err := analyzer.AnalyzeFile("../../test/data/REGISTER-Request.pcap")
		if err != nil {
			t.Fatalf("Failed to analyze file: %v", err)
		}

		// Verify basic packet analysis
		assert.NotEmpty(t, analysis.Packets, "Expected packets in analysis")
		
		// Verify first packet is a REGISTER request
		if assert.NotEmpty(t, analysis.Packets) {
			packet := analysis.Packets[0]
			assert.Equal(t, "REGISTER", packet.Method)
			assert.True(t, packet.IsRequest)
			assert.NotEmpty(t, packet.CallID)
		}

		// Verify call flow
		groups := analysis.GroupByCall()
		assert.Len(t, groups, 1, "Expected one call")

		for _, group := range groups {
			flow := group.BuildCallFlow(logger)
			diagram := flow.GenerateMermaid()

			// Verify diagram structure
			assert.Contains(t, diagram, "sequenceDiagram")
			assert.Contains(t, diagram, "participant sip_201_at_10_33_6_101")
			assert.Contains(t, diagram, "participant sip_server_at_10_33_6_102")
			assert.Contains(t, diagram, "sip_201_at_10_33_6_101->>sip_server_at_10_33_6_102: REGISTER")
			assert.Contains(t, diagram, "sip_server_at_10_33_6_102->>sip_201_at_10_33_6_101: 200")
		}
	})

	t.Run("register.pcap", func(t *testing.T) {
		// Test file analysis
		analysis, err := analyzer.AnalyzeFile("../../test/data/register.pcap")
		if err != nil {
			t.Fatalf("Failed to analyze file: %v", err)
		}

		// Verify basic packet analysis
		assert.NotEmpty(t, analysis.Packets, "Expected packets in analysis")
		
		// Verify first packet is a REGISTER request
		if assert.NotEmpty(t, analysis.Packets) {
			packet := analysis.Packets[0]
			assert.Equal(t, "REGISTER", packet.Method)
			assert.True(t, packet.IsRequest)
			assert.NotEmpty(t, packet.CallID)
		}

		// Verify call flow
		groups := analysis.GroupByCall()
		assert.Len(t, groups, 1, "Expected one call")

		for _, group := range groups {
			flow := group.BuildCallFlow(logger)
			diagram := flow.GenerateMermaid()

			// Verify diagram structure
			assert.Contains(t, diagram, "sequenceDiagram")
			assert.Contains(t, diagram, "participant sip_telephone1_at_172_16_98_101_transport_UDP")
			assert.Contains(t, diagram, "participant sip_server_at_172_16_98_101")
			assert.Contains(t, diagram, "sip_telephone1_at_172_16_98_101_transport_UDP->>sip_server_at_172_16_98_101: REGISTER")
			assert.Contains(t, diagram, "sip_server_at_172_16_98_101->>sip_telephone1_at_172_16_98_101_transport_UDP: 401")
			assert.Contains(t, diagram, "sip_telephone1_at_172_16_98_101_transport_UDP->>sip_server_at_172_16_98_101: REGISTER")
			assert.Contains(t, diagram, "sip_server_at_172_16_98_101->>sip_telephone1_at_172_16_98_101_transport_UDP: 200")
		}
	})
}