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

func TestAnalysis_GroupByCall(t *testing.T) {
	analysis := NewAnalysis()
	
	// Create test packets with different Call-IDs and timestamps
	now := time.Now()
	packets := []*SIPPacket{
		{
			PacketInfo: PacketInfo{
				Timestamp: now.Add(2 * time.Second),
				SrcIP:     "192.168.1.1",
				DstIP:     "192.168.1.2",
			},
			Method:    "BYE",
			CallID:    "call-1",
			IsRequest: true,
		},
		{
			PacketInfo: PacketInfo{
				Timestamp: now,
				SrcIP:     "192.168.1.1",
				DstIP:     "192.168.1.2",
			},
			Method:    "INVITE",
			CallID:    "call-1",
			IsRequest: true,
		},
		{
			PacketInfo: PacketInfo{
				Timestamp: now.Add(time.Second),
				SrcIP:     "192.168.1.2",
				DstIP:     "192.168.1.1",
			},
			Method:     "INVITE",
			StatusCode: 200,
			StatusDesc: "OK",
			CallID:     "call-1",
			IsRequest:  false,
		},
		{
			PacketInfo: PacketInfo{
				Timestamp: now,
				SrcIP:     "192.168.1.3",
				DstIP:     "192.168.1.4",
			},
			Method:    "REGISTER",
			CallID:    "call-2",
			IsRequest: true,
		},
	}

	// Add packets to analysis
	for _, packet := range packets {
		analysis.AddPacket(packet)
	}

	// Group packets by call
	groups := analysis.GroupByCall()

	// Verify number of groups
	assert.Len(t, groups, 2, "Expected 2 call groups")

	// Verify call-1 group
	call1Group, exists := groups["call-1"]
	assert.True(t, exists, "Expected call-1 group to exist")
	assert.Equal(t, "call-1", call1Group.CallID)
	assert.Len(t, call1Group.Packets, 3)

	// Verify chronological order of call-1 packets
	assert.Equal(t, "INVITE", call1Group.Packets[0].Method)
	assert.True(t, call1Group.Packets[0].IsRequest)
	assert.Equal(t, "INVITE", call1Group.Packets[1].Method)
	assert.False(t, call1Group.Packets[1].IsRequest)
	assert.Equal(t, "BYE", call1Group.Packets[2].Method)

	// Verify call-2 group
	call2Group, exists := groups["call-2"]
	assert.True(t, exists, "Expected call-2 group to exist")
	assert.Equal(t, "call-2", call2Group.CallID)
	assert.Len(t, call2Group.Packets, 1)
	assert.Equal(t, "REGISTER", call2Group.Packets[0].Method)
} 