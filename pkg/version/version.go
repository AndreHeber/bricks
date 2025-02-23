package version

import (
	"fmt"
	"runtime"
)

var (
	// Version holds the current version number
	Version = "0.1.0"

	// BuildDate holds the build date
	BuildDate = "unknown"

	// GitCommit holds the git commit hash
	GitCommit = "unknown"

	// GoVersion holds the version of Go used to build the binary
	GoVersion = runtime.Version()
)

// Info returns version information as a formatted string
func Info() string {
	return fmt.Sprintf("Version: %s\nGit Commit: %s\nBuild Date: %s\nGo Version: %s\n",
		Version, GitCommit, BuildDate, GoVersion)
}

// Short returns a short version string
func Short() string {
	return fmt.Sprintf("v%s (%s)", Version, GitCommit[:7])
} 