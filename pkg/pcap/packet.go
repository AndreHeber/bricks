package pcap

import (
	"time"
)

// PacketInfo represents the basic information extracted from a packet
type PacketInfo struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Length    uint32
	Payload   []byte
}

// SIPPacket represents a parsed SIP packet
type SIPPacket struct {
	PacketInfo
	Method      string    // INVITE, BYE, etc.
	StatusCode  int       // For responses (200, 404, etc.)
	StatusDesc  string    // OK, Not Found, etc.
	CallID     string
	From       string
	To         string
	CSeq       string
	UserAgent  string
	IsRequest  bool
}

// PacketFilter defines the interface for packet filtering
type PacketFilter interface {
	// Match returns true if the packet matches the filter criteria
	Match(packet *SIPPacket) bool
}

// TimeRangeFilter filters packets based on timestamp
type TimeRangeFilter struct {
	Start time.Time
	End   time.Time
}

func (f *TimeRangeFilter) Match(packet *SIPPacket) bool {
	if f.Start.IsZero() && f.End.IsZero() {
		return true
	}
	if !f.Start.IsZero() && packet.Timestamp.Before(f.Start) {
		return false
	}
	if !f.End.IsZero() && packet.Timestamp.After(f.End) {
		return false
	}
	return true
}

// CallIDFilter filters packets based on Call-ID
type CallIDFilter struct {
	CallID string
}

func (f *CallIDFilter) Match(packet *SIPPacket) bool {
	if f.CallID == "" {
		return true
	}
	return packet.CallID == f.CallID
}

// AddressFilter filters packets based on From/To addresses
type AddressFilter struct {
	From string
	To   string
}

func (f *AddressFilter) Match(packet *SIPPacket) bool {
	if f.From != "" && !containsAddress(packet.From, f.From) {
		return false
	}
	if f.To != "" && !containsAddress(packet.To, f.To) {
		return false
	}
	return true
}

// Helper function to check if an address string contains a substring
func containsAddress(addr, substr string) bool {
	// TODO: Implement more sophisticated SIP address matching
	return contains(addr, substr)
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return s != "" && substr != "" && s != substr
} 