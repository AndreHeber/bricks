package pcap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testLogger struct{}

func (l *testLogger) Info(msg string)  {}
func (l *testLogger) Error(msg string) {}

type mockFilter struct {
	matchResult bool
}

func (f *mockFilter) Match(packet *SIPPacket) bool {
	return f.matchResult
}

func TestAnalyzer_AddFilter(t *testing.T) {
	analyzer := NewAnalyzer(1024, &testLogger{})
	filter := &mockFilter{matchResult: true}
	
	analyzer.AddFilter(filter)
	
	assert.Len(t, analyzer.filters, 1)
	assert.Equal(t, filter, analyzer.filters[0])
}

func TestAnalyzer_MatchesFilters(t *testing.T) {
	analyzer := NewAnalyzer(1024, &testLogger{})
	
	// Test with no filters
	packet := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
			SrcPort:   5060,
			DstPort:   5061,
			Protocol:  "SIP",
			Length:    100,
			Payload:   []byte("test payload"),
		},
		IsRequest:  true,
		Method:     "INVITE",
		CallID:     "test-call-id",
		From:       "sip:alice@example.com",
		To:         "sip:bob@example.com",
		CSeq:       "1 INVITE",
		UserAgent:  "Test UA",
	}
	assert.True(t, analyzer.matchesFilters(packet))
	
	// Test with matching filter
	matchingFilter := &mockFilter{matchResult: true}
	analyzer.AddFilter(matchingFilter)
	assert.True(t, analyzer.matchesFilters(packet))
	
	// Test with non-matching filter
	nonMatchingFilter := &mockFilter{matchResult: false}
	analyzer.AddFilter(nonMatchingFilter)
	assert.False(t, analyzer.matchesFilters(packet))
}

func TestAnalyzer_AnalyzeFile(t *testing.T) {
	analyzer := NewAnalyzer(1024, &testLogger{})
	
	// Test with non-existent file
	analysis, err := analyzer.AnalyzeFile("nonexistent.pcap")
	assert.Error(t, err)
	assert.Nil(t, analysis)
}

func TestAnalysis_AddPacket(t *testing.T) {
	analysis := NewAnalysis()
	packet := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
			SrcPort:   5060,
			DstPort:   5061,
			Protocol:  "SIP",
			Length:    100,
			Payload:   []byte("test payload"),
		},
		IsRequest:  true,
		Method:     "INVITE",
		CallID:     "test-call-id",
		From:       "sip:alice@example.com",
		To:         "sip:bob@example.com",
		CSeq:       "1 INVITE",
		UserAgent:  "Test UA",
	}
	
	analysis.AddPacket(packet)
	
	assert.Len(t, analysis.Packets, 1)
	assert.Equal(t, packet, analysis.Packets[0])
}

func TestAnalysis_Print(t *testing.T) {
	analysis := NewAnalysis()
	packet := &SIPPacket{
		PacketInfo: PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
			SrcPort:   5060,
			DstPort:   5061,
			Protocol:  "SIP",
			Length:    100,
			Payload:   []byte("test payload"),
		},
		IsRequest:  true,
		Method:     "INVITE",
		CallID:     "test-call-id",
		From:       "sip:alice@example.com",
		To:         "sip:bob@example.com",
		CSeq:       "1 INVITE",
		UserAgent:  "Test UA",
	}
	
	analysis.AddPacket(packet)
	
	// Just verify that Print doesn't panic
	analysis.Print()
} 