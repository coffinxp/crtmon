package main

import (
	"encoding/json"
	"fmt"
	"time"
)

func outputJSON(domain, target string, entry CertEntry) {
	data := map[string]interface{}{
		"domain":     domain,
		"target":     target,
		"not_before": entry.NotBefore.Format(time.RFC3339),
		"not_after":  entry.NotAfter.Format(time.RFC3339),
		"issuer":     entry.Issuer,
		"log_url":    entry.LogURL,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		outputJSONError(err.Error())
		return
	}
	fmt.Println(string(jsonBytes))
}

func outputJSONError(errMsg string) {
	data := map[string]interface{}{
		"error":     errMsg,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	jsonBytes, _ := json.Marshal(data)
	fmt.Println(string(jsonBytes))
}
