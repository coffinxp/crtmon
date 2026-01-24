package main

import (
	"fmt"
	"strings"
	"time"
)

func buildDiscordPayload(target string, domains []string) map[string]interface{} {
	domainList := strings.Join(domains, "\n")

	return map[string]interface{}{
		"tts": false,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s  [%d]", target, len(domains)),
				"description": fmt.Sprintf("```\n%s\n```", domainList),
				"color":       2829617,
				// "author": map[string]string{
				// 	"name": "1hehaq/ceye",
				// 	"url":  "https://github.com/1hehaq/ceye",
				// },
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}
}

func buildTelegramMessage(target string, domains []string) string {
	domainList := strings.Join(domains, "\n")
	return fmt.Sprintf("*%s* [%d]\n```%s```", target, len(domains), domainList)
}

func buildNtfyMessage(target string, domains []string) string {
	domainList := strings.Join(domains, "\n")
	return fmt.Sprintf("%s [%d]\n%s", target, len(domains), domainList)
}
