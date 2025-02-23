package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AndreHeber/pcap-analyzer/pkg/pcap"
	"github.com/AndreHeber/pcap-analyzer/pkg/version"

	"github.com/fatih/color"
)

// Config holds the command line configuration
type Config struct {
	inputFile    string
	outputFile   string
	filterCallID string
	filterFrom   string
	filterTo     string
	timeStart    string
	timeEnd      string
	debug        bool
}

type ColorLogger struct{}

func (l *ColorLogger) Info(msg string)  { color.Yellow(msg) }
func (l *ColorLogger) Error(msg string) { color.Red(msg) }

func parseFlags() *Config {
	cfg := &Config{}

	// Version flags
	versionFlag := flag.Bool("version", false, "print version information")
	shortVersionFlag := flag.Bool("v", false, "print short version information")

	// Output control
	flag.StringVar(&cfg.outputFile, "o", "", "output file (default: stdout)")
	
	// Filters
	flag.StringVar(&cfg.filterCallID, "call-id", "", "filter by SIP Call-ID")
	flag.StringVar(&cfg.filterFrom, "from", "", "filter by From address")
	flag.StringVar(&cfg.filterTo, "to", "", "filter by To address")
	flag.StringVar(&cfg.timeStart, "start", "", "start time (format: YYYY-MM-DD HH:MM:SS)")
	flag.StringVar(&cfg.timeEnd, "end", "", "end time (format: YYYY-MM-DD HH:MM:SS)")
	
	// Debug mode
	flag.BoolVar(&cfg.debug, "debug", false, "enable debug logging")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <pcap-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "A tool to generate Mermaid sequence diagrams from PCAP files containing SIP traffic.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s capture.pcap                    # Basic usage\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -o flow.md capture.pcap         # Save to file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --call-id=abc123 capture.pcap   # Filter by Call-ID\n", os.Args[0])
	}

	flag.Parse()

	// Handle version flags
	if *versionFlag {
		fmt.Print(version.Info())
		os.Exit(0)
	}
	if *shortVersionFlag {
		fmt.Println(version.Short())
		os.Exit(0)
	}

	// Get input file from positional argument
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	cfg.inputFile = args[0]

	return cfg
}

func parseTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation("2006-01-02 15:04:05", timeStr, time.Local)
}

func main() {
	cfg := parseFlags()

	logger := &ColorLogger{}
	if cfg.debug {
		logger.Info("Debug mode enabled")
	}

	analyzer := pcap.NewAnalyzer(100, logger)

	// Add filters based on configuration
	if cfg.filterCallID != "" {
		analyzer.AddFilter(&pcap.CallIDFilter{CallID: cfg.filterCallID})
		if cfg.debug {
			logger.Info(fmt.Sprintf("Added Call-ID filter: %s", cfg.filterCallID))
		}
	}

	if cfg.filterFrom != "" || cfg.filterTo != "" {
		analyzer.AddFilter(&pcap.AddressFilter{
			From: cfg.filterFrom,
			To:   cfg.filterTo,
		})
		if cfg.debug {
			logger.Info(fmt.Sprintf("Added address filter - From: %s, To: %s", cfg.filterFrom, cfg.filterTo))
		}
	}

	startTime, err := parseTime(cfg.timeStart)
	if err != nil {
		logger.Error(fmt.Sprintf("Invalid start time format: %v", err))
		os.Exit(1)
	}

	endTime, err := parseTime(cfg.timeEnd)
	if err != nil {
		logger.Error(fmt.Sprintf("Invalid end time format: %v", err))
		os.Exit(1)
	}

	if !startTime.IsZero() || !endTime.IsZero() {
		analyzer.AddFilter(&pcap.TimeRangeFilter{
			Start: startTime,
			End:   endTime,
		})
		if cfg.debug {
			logger.Info(fmt.Sprintf("Added time filter - Start: %v, End: %v", startTime, endTime))
		}
	}

	// Analyze PCAP file
	analysis, err := analyzer.AnalyzeFile(cfg.inputFile)
	if err != nil {
		logger.Error(fmt.Sprintf("Error analyzing pcap file: %v", err))
		os.Exit(1)
	}

	if len(analysis.Packets) == 0 {
		logger.Error("No SIP packets found in the capture")
		os.Exit(1)
	}

	if cfg.debug {
		logger.Info(fmt.Sprintf("Found %d SIP packets", len(analysis.Packets)))
		// Print raw packet data
		analysis.Print()
	}

	// Group packets by call and generate Mermaid diagrams
	groups := analysis.GroupByCall()
	if len(groups) == 0 {
		logger.Error("No SIP calls found in the capture")
		os.Exit(1)
	}

	if cfg.debug {
		logger.Info(fmt.Sprintf("Found %d SIP calls", len(groups)))
	}

	// Generate Mermaid diagrams for each call
	var output strings.Builder
	for callID, group := range groups {
		if cfg.debug {
			logger.Info(fmt.Sprintf("Generating diagram for call: %s", callID))
		}

		flow := group.BuildCallFlow()
		diagram := flow.GenerateMermaid()
		output.WriteString(diagram)
		output.WriteString("\n\n")
	}

	// Handle output
	if cfg.outputFile != "" {
		err = os.WriteFile(cfg.outputFile, []byte(output.String()), 0644)
		if err != nil {
			logger.Error(fmt.Sprintf("Error writing output file: %v", err))
			os.Exit(1)
		}
		if cfg.debug {
			logger.Info(fmt.Sprintf("Output written to: %s", cfg.outputFile))
		}
	} else {
		fmt.Println(output.String())
	}
} 