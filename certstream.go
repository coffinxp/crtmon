package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

type CertEntry struct {
	Domains   []string
	NotBefore time.Time
	NotAfter  time.Time
	Issuer    string
	LogURL    string
}

type CTMonitor struct {
	entryChan chan CertEntry
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewCTMonitor() *CTMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	log.SetOutput(io.Discard)
	log.SetFlags(0)

	return &CTMonitor{
		entryChan: make(chan CertEntry, 5000),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (m *CTMonitor) Start() <-chan CertEntry {
	go m.run()
	return m.entryChan
}

func (m *CTMonitor) Stop() {
	m.cancel()
	m.wg.Wait()
	close(m.entryChan)
}

func (m *CTMonitor) run() {
	logs, err := fetchLogList()
	if err != nil {
		logger.Error("failed to fetch CT log list", "error", err)
		return
	}

	logger.Info("fetched CT log list", "usable_logs", len(logs))

	for _, logInfo := range logs {
		m.wg.Add(1)
		go m.monitorLog(logInfo)
	}
}

func fetchLogList() ([]*loglist3.Log, error) {
	resp, err := http.Get(loglist3.LogListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch log list: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read log list: %w", err)
	}

	var ll loglist3.LogList
	if err := json.Unmarshal(body, &ll); err != nil {
		return nil, fmt.Errorf("failed to parse log list: %w", err)
	}

	var usableLogs []*loglist3.Log
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			if log.State != nil && log.State.Usable != nil {
				usableLogs = append(usableLogs, log)
			}
		}
	}

	return usableLogs, nil
}

func (m *CTMonitor) monitorLog(logInfo *loglist3.Log) {
	defer m.wg.Done()

	logURL := logInfo.URL
	if !strings.HasPrefix(logURL, "https://") {
		logURL = "https://" + logURL
	}
	logURL = strings.TrimSuffix(logURL, "/")
	httpClient := &http.Client{Timeout: 180 * time.Second}

	logClient, err := client.New(logURL, httpClient, jsonclient.Options{})
	if err != nil {
		logger.Warn("failed to create log client", "log", logInfo.Description, "error", err)
		return
	}

	sth, err := logClient.GetSTH(m.ctx)
	if err != nil {
		logger.Warn("failed to get STH", "log", logInfo.Description, "error", err)
		return
	}

	opts := scanner.FetcherOptions{
		BatchSize:     512,
		ParallelFetch: 2,
		StartIndex:    int64(sth.TreeSize),
		EndIndex:      0,
		Continuous:    true,
	}

	fetcher := scanner.NewFetcher(logClient, &opts)

	logger.Debug("monitoring CT log", "from", logInfo.Description)

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		err := fetcher.Run(m.ctx, func(batch scanner.EntryBatch) {
			for i, entry := range batch.Entries {
				m.processEntry(entry, batch.Start+int64(i), logURL)
			}
		})

		if err != nil {
			if m.ctx.Err() != nil {
				return
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (m *CTMonitor) processEntry(entry ct.LeafEntry, index int64, logURL string) {
	rle, err := ct.RawLogEntryFromLeaf(index, &entry)
	if err != nil {
		return
	}

	var cert *x509.Certificate

	switch rle.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = x509.ParseCertificate(rle.Cert.Data)
	case ct.PrecertLogEntryType:
		cert, err = x509.ParseTBSCertificate(rle.Cert.Data)
	default:
		return
	}

	if err != nil {
		return
	}

	domains := extractDomains(cert)
	if len(domains) == 0 {
		return
	}

	select {
	case m.entryChan <- CertEntry{
		Domains:   domains,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Issuer:    cert.Issuer.CommonName,
		LogURL:    logURL,
	}:
	default:
	}
}

func extractDomains(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var domains []string

	if cert.Subject.CommonName != "" {
		seen[cert.Subject.CommonName] = true
		domains = append(domains, cert.Subject.CommonName)
	}

	for _, dns := range cert.DNSNames {
		if !seen[dns] {
			seen[dns] = true
			domains = append(domains, dns)
		}
	}

	return domains
}

func CertStreamEventStream() <-chan CertEntry {
	monitor := NewCTMonitor()
	return monitor.Start()
}
