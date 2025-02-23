VERSION ?= 0.1.0
GIT_COMMIT = $(shell git rev-parse HEAD)
BUILD_DATE = $(shell date -u '+%Y-%m-%d %H:%M:%S')
LDFLAGS = -X github.com/AndreHeber/pcap-analyzer/pkg/version.Version=$(VERSION) \
          -X github.com/AndreHeber/pcap-analyzer/pkg/version.GitCommit=$(GIT_COMMIT) \
          -X 'github.com/AndreHeber/pcap-analyzer/pkg/version.BuildDate=$(BUILD_DATE)'

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o pcap-analyzer ./cmd/pcap-analyzer

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/pcap-analyzer

.PHONY: clean
clean:
	rm -f pcap-analyzer

.PHONY: test
test:
	go test -v ./...

.DEFAULT_GOAL := build 