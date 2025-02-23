package sip

import (
	"testing"
)

func TestParseMessage_Request(t *testing.T) {
	input := `INVITE sip:bob@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@biloxi.com>
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com
s=Session SDP
c=IN IP4 pc33.atlanta.com
t=0 0
m=audio 49172 RTP/AVP 0
a=rtpmap:0 PCMU/8000`

	msg, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("Failed to parse SIP request: %v", err)
	}

	// Test start line
	if !msg.StartLine.IsRequest {
		t.Error("Expected request message")
	}
	if msg.StartLine.Method != "INVITE" {
		t.Errorf("Expected method INVITE, got %s", msg.StartLine.Method)
	}
	if msg.StartLine.RequestURI != "sip:bob@biloxi.com" {
		t.Errorf("Expected URI sip:bob@biloxi.com, got %s", msg.StartLine.RequestURI)
	}
	if msg.StartLine.Version != "SIP/2.0" {
		t.Errorf("Expected version SIP/2.0, got %s", msg.StartLine.Version)
	}

	// Test headers
	tests := []struct {
		header string
		want   string
	}{
		{CallID, "a84b4c76e66710@pc33.atlanta.com"},
		{From, "Alice <sip:alice@atlanta.com>;tag=1928301774"},
		{To, "Bob <sip:bob@biloxi.com>"},
		{CSeq, "314159 INVITE"},
		{ContentType, "application/sdp"},
		{ContentLength, "142"},
	}

	for _, tt := range tests {
		if got := msg.Headers.GetHeader(tt.header); got != tt.want {
			t.Errorf("Header %s = %s; want %s", tt.header, got, tt.want)
		}
	}

	// Test body
	expectedBodyStart := "v=0"
	if len(msg.Body) == 0 || msg.Body[:3] != expectedBodyStart {
		t.Errorf("Body should start with %s", expectedBodyStart)
	}
}

func TestParseMessage_Response(t *testing.T) {
	input := `SIP/2.0 200 OK
Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bKnashds8
To: Bob <sip:bob@biloxi.com>;tag=2214608697
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:bob@client.biloxi.com>
Content-Length: 0

`

	msg, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("Failed to parse SIP response: %v", err)
	}

	// Test start line
	if msg.StartLine.IsRequest {
		t.Error("Expected response message")
	}
	if msg.StartLine.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", msg.StartLine.StatusCode)
	}
	if msg.StartLine.Reason != "OK" {
		t.Errorf("Expected reason OK, got %s", msg.StartLine.Reason)
	}
	if msg.StartLine.Version != "SIP/2.0" {
		t.Errorf("Expected version SIP/2.0, got %s", msg.StartLine.Version)
	}

	// Test headers
	tests := []struct {
		header string
		want   string
	}{
		{CallID, "a84b4c76e66710@pc33.atlanta.com"},
		{From, "Alice <sip:alice@atlanta.com>;tag=1928301774"},
		{To, "Bob <sip:bob@biloxi.com>;tag=2214608697"},
		{CSeq, "314159 INVITE"},
		{ContentLength, "0"},
	}

	for _, tt := range tests {
		if got := msg.Headers.GetHeader(tt.header); got != tt.want {
			t.Errorf("Header %s = %s; want %s", tt.header, got, tt.want)
		}
	}

	// Test empty body
	if msg.Body != "" {
		t.Error("Expected empty body")
	}
}

func TestParseMessage_InvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "invalid start line",
			input: "INVITE\n",
		},
		{
			name:  "invalid status code",
			input: "SIP/2.0 2xx OK\n",
		},
		{
			name:  "invalid header format",
			input: "INVITE sip:bob@biloxi.com SIP/2.0\nInvalid Header Line\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMessage([]byte(tt.input))
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestHeaders_MultipleValues(t *testing.T) {
	input := `INVITE sip:bob@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com
Record-Route: <sip:server10.biloxi.com;lr>
Record-Route: <sip:bigbox3.site3.atlanta.com;lr>
Content-Length: 0

`

	msg, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("Failed to parse SIP message: %v", err)
	}

	// Test Via headers
	vias := msg.Headers.GetHeaderValues("Via")
	if len(vias) != 2 {
		t.Errorf("Expected 2 Via headers, got %d", len(vias))
	}
	expectedVia1 := "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds"
	if vias[0] != expectedVia1 {
		t.Errorf("First Via = %s; want %s", vias[0], expectedVia1)
	}

	// Test Record-Route headers
	routes := msg.Headers.GetHeaderValues("Record-Route")
	if len(routes) != 2 {
		t.Errorf("Expected 2 Record-Route headers, got %d", len(routes))
	}
	expectedRoute1 := "<sip:server10.biloxi.com;lr>"
	if routes[0] != expectedRoute1 {
		t.Errorf("First Record-Route = %s; want %s", routes[0], expectedRoute1)
	}
} 