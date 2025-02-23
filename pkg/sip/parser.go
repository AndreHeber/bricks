package sip

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Message represents a SIP message (request or response)
type Message struct {
	StartLine StartLine
	Headers   Headers
	Body      string
}

// StartLine represents either a Request-Line or a Status-Line
type StartLine struct {
	Method     string // INVITE, ACK, BYE, etc.
	RequestURI string // For requests
	Version    string // SIP/2.0
	StatusCode int    // For responses (200, 404, etc.)
	Reason     string // For responses (OK, Not Found, etc.)
	IsRequest  bool
}

// Headers represents SIP message headers
type Headers map[string][]string

// Common SIP headers
const (
	CallID          = "Call-ID"
	From            = "From"
	To              = "To"
	Via             = "Via"
	CSeq            = "CSeq"
	Contact         = "Contact"
	ContentType     = "Content-Type"
	ContentLength   = "Content-Length"
	UserAgent       = "User-Agent"
	MaxForwards     = "Max-Forwards"
	Authorization   = "Authorization"
	WWWAuthenticate = "WWW-Authenticate"
)

// ParseMessage parses a SIP message from raw bytes
func ParseMessage(data []byte) (*Message, error) {
	reader := bufio.NewReader(strings.NewReader(string(data)))
	
	// Read the start line
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading start line: %w", err)
	}
	firstLine = strings.TrimSpace(firstLine)

	startLine, err := parseStartLine(firstLine)
	if err != nil {
		return nil, fmt.Errorf("parsing start line: %w", err)
	}

	// Parse headers
	headers := make(Headers)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading header line: %w", err)
		}
		line = strings.TrimSpace(line)
		
		// Empty line indicates end of headers
		if line == "" {
			break
		}

		// Parse header line
		name, value, err := parseHeader(line)
		if err != nil {
			return nil, fmt.Errorf("parsing header: %w", err)
		}
		headers[name] = append(headers[name], value)
	}

	// Read body if Content-Length is present
	var body string
	if contentLengths, exists := headers[ContentLength]; exists && len(contentLengths) > 0 {
		length, err := strconv.Atoi(contentLengths[0])
		if err == nil && length > 0 {
			bodyBytes := make([]byte, length)
			_, err = reader.Read(bodyBytes)
			if err != nil {
				return nil, fmt.Errorf("reading body: %w", err)
			}
			body = string(bodyBytes)
		}
	}

	return &Message{
		StartLine: *startLine,
		Headers:   headers,
		Body:      body,
	}, nil
}

// parseStartLine parses the first line of a SIP message
func parseStartLine(line string) (*StartLine, error) {
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid start line: %s", line)
	}

	startLine := &StartLine{}
	
	// Check if it's a request or response
	if strings.HasPrefix(parts[0], "SIP/") {
		// Response: SIP/2.0 200 OK
		startLine.IsRequest = false
		startLine.Version = parts[0]
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid status code: %s", parts[1])
		}
		startLine.StatusCode = code
		startLine.Reason = strings.Join(parts[2:], " ")
	} else {
		// Request: INVITE sip:user@domain SIP/2.0
		startLine.IsRequest = true
		startLine.Method = parts[0]
		startLine.RequestURI = parts[1]
		startLine.Version = parts[2]
	}

	return startLine, nil
}

// parseHeader parses a single header line
func parseHeader(line string) (string, string, error) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header line: %s", line)
	}

	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	return name, value, nil
}

// GetHeader returns the first value of a header
func (h Headers) GetHeader(name string) string {
	if values, exists := h[name]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaderValues returns all values of a header
func (h Headers) GetHeaderValues(name string) []string {
	if values, exists := h[name]; exists {
		return values
	}
	return nil
} 