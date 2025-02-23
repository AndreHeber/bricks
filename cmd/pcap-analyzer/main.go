package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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

func main() {
	cfg := parseFlags()

	logger := &ColorLogger{}
	if cfg.debug {
		logger.Info("Debug mode enabled")
	}

	analyzer := pcap.NewAnalyzer(100, logger)

	analysis, err := analyzer.AnalyzeFile(cfg.inputFile)
	if err != nil {
		log.Fatalf("Error analyzing pcap file: %v", err)
	}

	// TODO: Apply filters based on cfg
	// TODO: Generate Mermaid diagram
	// TODO: Handle output to file if specified

	analysis.Print()
} 