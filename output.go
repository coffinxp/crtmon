package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	outputFilePath string
	outputFd       *os.File
	outputWriter   *bufio.Writer
	outputMu       sync.Mutex
)

// initOutputFile opens the file in append+create mode.
// Called once from main() when -o is provided.
func initOutputFile(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	outputFd = f
	outputWriter = bufio.NewWriter(f)
	outputFilePath = path
	return nil
}

// writeToOutputFile appends a single matched domain line to the file.
// Format:  2026-05-13T11:07:00  target.com  sub.target.com
func writeToOutputFile(domain, target string) {
	if outputWriter == nil {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	ts := time.Now().Format("2006-01-02T15:04:05")
	line := fmt.Sprintf("%s\t%s\t%s\n", ts, target, domain)
	_, _ = outputWriter.WriteString(line)
	_ = outputWriter.Flush() // flush every line so file is always up-to-date
}

// closeOutputFile flushes and closes the file. Call on shutdown.
func closeOutputFile() {
	if outputFd == nil {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	_ = outputWriter.Flush()
	_ = outputFd.Close()
}
