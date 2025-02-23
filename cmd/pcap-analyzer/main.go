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

type ColorLogger struct{}

func (l *ColorLogger) Info(msg string)  { color.Yellow(msg) }
func (l *ColorLogger) Error(msg string) { color.Red(msg) }

func main() {
	// Parse command line flags
	versionFlag := flag.Bool("version", false, "print version information")
	shortVersionFlag := flag.Bool("v", false, "print short version information")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <pcap-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Handle version flags
	if *versionFlag {
		fmt.Print(version.Info())
		return
	}
	if *shortVersionFlag {
		fmt.Println(version.Short())
		return
	}

	// Check for pcap file argument
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	logger := &ColorLogger{}
	analyzer := pcap.NewAnalyzer(100, logger)

	analysis, err := analyzer.AnalyzeFile(args[0])
	if err != nil {
		log.Fatalf("Error analyzing pcap file: %v", err)
	}

	analysis.Print()
} 