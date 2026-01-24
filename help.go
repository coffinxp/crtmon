package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var cyanCommands = []string{"crtmon", "nohup", "crontab", "echo", "cat", "reboot"}

func isCyanCommand(cmd string) bool {
	for _, c := range cyanCommands {
		if c == cmd {
			return true
		}
	}
	return false
}

func displayHelp() {
	cmdStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	argStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	flagStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))

	printBanner()
	fmt.Println(successStyle.Render(" usage:"))
	fmt.Printf("    %s domains.txt | %s -target -\n", cmdStyle.Render("cat"), cmdStyle.Render("crtmon"))
	fmt.Printf("    %s -target %s -config %s -notify=%s\n", cmdStyle.Render("crtmon"), argStyle.Render("example.com"), argStyle.Render("custom.yaml"), argStyle.Render("discord,ntfy"))
	fmt.Printf("    %s -target %s\n", cmdStyle.Render("crtmon"), argStyle.Render("domains.txt"))
	fmt.Printf("    %s \"@reboot %s %s -target %s > /tmp/crtmon.log 2>&1 &\" | %s -\n\n", cmdStyle.Render("echo"), cmdStyle.Render("nohup"), cmdStyle.Render("crtmon"), argStyle.Render("example.com"), cmdStyle.Render("crontab"))

	fmt.Println(successStyle.Render(" options:"))
	fmt.Printf("    %s      target domain(s) to monitor:\n", flagStyle.Render("-target"))
	fmt.Printf("                   single domain: %s\n", argStyle.Render("-target example.com"))
	fmt.Printf("                   file with domains: %s\n", argStyle.Render("-target targets.txt"))
	fmt.Printf("                   stdin: %s\n", argStyle.Render("-target -"))
	fmt.Printf("    %s       scope keyword to filter subdomains\n", flagStyle.Render("-scope"))
	fmt.Printf("    %s      path to configuration file (default: ~/.config/crtmon/provider.yaml)\n", flagStyle.Render("-config"))
	fmt.Printf("    %s      notification provider: discord, telegram, ntfy (comma-separated; both/all)\n", flagStyle.Render("-notify"))
	fmt.Printf("    %s        output results in JSON format (suppresses all other output)\n", flagStyle.Render("-json"))
	fmt.Printf("    %s     show version\n", flagStyle.Render("-version"))
	fmt.Printf("    %s      update to latest version\n", flagStyle.Render("-update"))
	fmt.Printf("    %s    show this help message\n\n", flagStyle.Render("-h, -help"))

	fmt.Println(successStyle.Render(" configuration:"))
	fmt.Printf("    %s config file location: ~/.config/crtmon/provider.yaml\n", argStyle.Render("•"))
	fmt.Printf("    %s supports multiple targets and notification providers\n\n", argStyle.Render("•"))

	fmt.Println(argStyle.Render(" monitor your targets real time via certificate transparency logs"))
	fmt.Println(argStyle.Render(" powered by github.com/google/certificate-transparency-go"))
	fmt.Println()
}
