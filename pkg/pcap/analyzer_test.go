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

func TestCallGroup_BuildCallFlow(t *testing.T) {
	now := time.Now()
	group := &CallGroup{
		CallID: "test-call-1",
		Packets: []*SIPPacket{
			{
				PacketInfo: PacketInfo{
					Timestamp: now,
					SrcIP:     "192.168.1.1",
					DstIP:     "192.168.1.2",
					SrcPort:   5060,
					DstPort:   5060,
				},
				Method:    "INVITE",
				CallID:    "test-call-1",
				From:      "Alice <sip:alice@atlanta.com>",
				To:        "Bob <sip:bob@biloxi.com>",
				IsRequest: true,
			},
			{
				PacketInfo: PacketInfo{
					Timestamp: now.Add(time.Second),
					SrcIP:     "192.168.1.2",
					DstIP:     "192.168.1.1",
					SrcPort:   5060,
					DstPort:   5060,
				},
				Method:     "INVITE",
				CallID:     "test-call-1",
				From:       "Alice <sip:alice@atlanta.com>",
				To:        "Bob <sip:bob@biloxi.com>",
				StatusCode: 200,
				StatusDesc: "OK",
				IsRequest:  false,
			},
			{
				PacketInfo: PacketInfo{
					Timestamp: now.Add(2 * time.Second),
					SrcIP:     "192.168.1.1",
					DstIP:     "192.168.1.2",
					SrcPort:   5060,
					DstPort:   5060,
				},
				Method:    "BYE",
				CallID:    "test-call-1",
				From:      "Alice <sip:alice@atlanta.com>",
				To:        "Bob <sip:bob@biloxi.com>",
				IsRequest: true,
			},
		},
	}

	flow := group.BuildCallFlow()

	// Verify call flow basics
	assert.Equal(t, "test-call-1", flow.CallID)
	assert.Len(t, flow.Participants, 2)
	assert.Len(t, flow.Interactions, 3)

	// Verify participants
	aliceURI := "sip:alice@atlanta.com"
	bobURI := "sip:bob@biloxi.com"
	
	alice, exists := flow.Participants[aliceURI]
	assert.True(t, exists)
	assert.Equal(t, aliceURI, alice.URI)
	assert.Equal(t, "192.168.1.1:5060", alice.Address)

	bob, exists := flow.Participants[bobURI]
	assert.True(t, exists)
	assert.Equal(t, bobURI, bob.URI)
	assert.Equal(t, "192.168.1.2:5060", bob.Address)

	// Verify interactions in sequence
	interactions := flow.Interactions
	
	// First interaction: INVITE request
	assert.Equal(t, now, interactions[0].Timestamp)
	assert.Equal(t, alice, interactions[0].From)
	assert.Equal(t, bob, interactions[0].To)
	assert.Equal(t, "INVITE", interactions[0].Method)
	assert.True(t, interactions[0].IsRequest)
	assert.Equal(t, 0, interactions[0].Status)

	// Second interaction: 200 OK response
	assert.Equal(t, now.Add(time.Second), interactions[1].Timestamp)
	assert.Equal(t, alice, interactions[1].From)
	assert.Equal(t, bob, interactions[1].To)
	assert.Equal(t, "INVITE", interactions[1].Method)
	assert.False(t, interactions[1].IsRequest)
	assert.Equal(t, 200, interactions[1].Status)

	// Third interaction: BYE request
	assert.Equal(t, now.Add(2*time.Second), interactions[2].Timestamp)
	assert.Equal(t, alice, interactions[2].From)
	assert.Equal(t, bob, interactions[2].To)
	assert.Equal(t, "BYE", interactions[2].Method)
	assert.True(t, interactions[2].IsRequest)
	assert.Equal(t, 0, interactions[2].Status)
}

func TestExtractParticipantInfo(t *testing.T) {
	tests := []struct {
		name         string
		sipAddr      string
		ip          string
		port         uint16
		expectedURI  string
		expectedAddr string
	}{
		{
			name:         "Full SIP address",
			sipAddr:      "Alice <sip:alice@atlanta.com>",
			ip:          "192.168.1.1",
			port:        5060,
			expectedURI: "sip:alice@atlanta.com",
			expectedAddr: "192.168.1.1:5060",
		},
		{
			name:         "URI only",
			sipAddr:      "sip:bob@biloxi.com",
			ip:          "192.168.1.2",
			port:        5061,
			expectedURI: "sip:bob@biloxi.com",
			expectedAddr: "192.168.1.2:5061",
		},
		{
			name:         "Empty SIP address",
			sipAddr:      "",
			ip:          "192.168.1.3",
			port:        5062,
			expectedURI: "",
			expectedAddr: "192.168.1.3:5062",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, addr := extractParticipantInfo(tt.sipAddr, tt.ip, tt.port)
			assert.Equal(t, tt.expectedURI, uri)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}

func TestCallFlow_GenerateMermaid(t *testing.T) {
	// Create a test call flow
	flow := &CallFlow{
		CallID: "test-call-1",
		Participants: map[string]*Participant{
			"sip:alice@atlanta.com": {
				URI:     "sip:alice@atlanta.com",
				Address: "192.168.1.1:5060",
			},
			"sip:bob@biloxi.com": {
				URI:     "sip:bob@biloxi.com",
				Address: "192.168.1.2:5060",
			},
		},
		Interactions: []*Interaction{
			{
				Timestamp: time.Now(),
				From: &Participant{
					URI:     "sip:alice@atlanta.com",
					Address: "192.168.1.1:5060",
				},
				To: &Participant{
					URI:     "sip:bob@biloxi.com",
					Address: "192.168.1.2:5060",
				},
				Method:    "INVITE",
				IsRequest: true,
			},
			{
				Timestamp: time.Now().Add(time.Second),
				From: &Participant{
					URI:     "sip:alice@atlanta.com",
					Address: "192.168.1.1:5060",
				},
				To: &Participant{
					URI:     "sip:bob@biloxi.com",
					Address: "192.168.1.2:5060",
				},
				Method:    "INVITE",
				Status:    200,
				IsRequest: false,
			},
		},
	}

	mermaid := flow.GenerateMermaid()

	// Verify Mermaid diagram structure
	assert.Contains(t, mermaid, "sequenceDiagram")
	assert.Contains(t, mermaid, "title SIP Call Flow - test-call-1")

	// Verify participants
	assert.Contains(t, mermaid, "participant sip_alice_at_atlanta_com")
	assert.Contains(t, mermaid, "participant sip_bob_at_biloxi_com")

	// Verify interactions
	assert.Contains(t, mermaid, "sip_alice_at_atlanta_com->>sip_bob_at_biloxi_com: INVITE")
	assert.Contains(t, mermaid, "sip_bob_at_biloxi_com-->sip_alice_at_atlanta_com: 200 INVITE")
}

func TestCleanMermaidName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SIP URI",
			input:    "sip:alice@atlanta.com",
			expected: "sip_alice_at_atlanta_com",
		},
		{
			name:     "Full SIP address",
			input:    "Alice <sip:alice@atlanta.com>",
			expected: "Alice_sip_alice_at_atlanta_com",
		},
		{
			name:     "IP address",
			input:    "192.168.1.1:5060",
			expected: "192_168_1_1_5060",
		},
		{
			name:     "Special characters",
			input:    "user;tag=1234,branch=xyz",
			expected: "user_tag_1234_branch_xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanMermaidName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetParticipantName(t *testing.T) {
	tests := []struct {
		name     string
		p        *Participant
		expected string
	}{
		{
			name: "URI present",
			p: &Participant{
				URI:     "sip:alice@atlanta.com",
				Address: "192.168.1.1:5060",
			},
			expected: "sip:alice@atlanta.com",
		},
		{
			name: "URI empty",
			p: &Participant{
				URI:     "",
				Address: "192.168.1.1:5060",
			},
			expected: "192.168.1.1:5060",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getParticipantName(tt.p)
			assert.Equal(t, tt.expected, result)
		})
	}
} 