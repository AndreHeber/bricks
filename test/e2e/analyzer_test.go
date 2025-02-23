package e2e

import (
	"testing"
	"time"

	"github.com/AndreHeber/pcap-analyzer/pkg/pcap"
	"github.com/stretchr/testify/assert"
)

type testLogger struct{}

func (l *testLogger) Info(msg string)  {}
func (l *testLogger) Error(msg string) {}

func TestAnalyzer_E2E(t *testing.T) {
	logger := &testLogger{}
	analyzer := pcap.NewAnalyzer(100, logger)

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

	// Test packet filtering with Call-ID
	callID := analysis.Packets[0].CallID
	filter := &pcap.CallIDFilter{CallID: callID}
	analyzer.AddFilter(filter)

	filteredAnalysis, err := analyzer.AnalyzeFile("../../test/data/REGISTER-Request.pcap")
	if err != nil {
		t.Fatalf("Failed to analyze file with filter: %v", err)
	}

	// Verify filtered packets
	assert.NotEmpty(t, filteredAnalysis.Packets, "Expected packets after Call-ID filtering")
	for _, packet := range filteredAnalysis.Packets {
		assert.Equal(t, callID, packet.CallID, "All packets should have the filtered Call-ID")
	}

	// Test time range filter with a very wide range
	timeFilter := &pcap.TimeRangeFilter{
		Start: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),  // Year 2000
		End:   time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),  // Year 2030
	}
	analyzer.AddFilter(timeFilter)

	timeFilteredAnalysis, err := analyzer.AnalyzeFile("../../test/data/REGISTER-Request.pcap")
	if err != nil {
		t.Fatalf("Failed to analyze file with time filter: %v", err)
	}

	// Verify time filtered packets
	assert.NotEmpty(t, timeFilteredAnalysis.Packets, "Expected packets after time filtering")
	
	// Print the first packet's timestamp for debugging
	if len(timeFilteredAnalysis.Packets) > 0 {
		t.Logf("First packet timestamp: %v", timeFilteredAnalysis.Packets[0].Timestamp)
	}
}