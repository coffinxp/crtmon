package main

import (
	"fmt"
	"runtime"

	"github.com/charmbracelet/lipgloss"
)

var (
	Version   = "1.1.1"
	GitCommit = "dev"
	BuildDate = ""
)

func displayVersion() {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

	fmt.Println()
	fmt.Printf("%s %s\n", cyan.Render("crtmon"), dim.Render("v"+Version))
	fmt.Println()
	fmt.Printf("  %s  %s\n", label.Render("commit:"), dim.Render(GitCommit))
	fmt.Printf("  %s   %s\n", label.Render("built:"), dim.Render(BuildDate))
	fmt.Printf("  %s      %s\n", label.Render("go:"), dim.Render(runtime.Version()))
	fmt.Printf("  %s %s/%s\n", label.Render("platform:"), dim.Render(runtime.GOOS), dim.Render(runtime.GOARCH))
	fmt.Println()
}
