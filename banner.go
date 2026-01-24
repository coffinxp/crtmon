package main

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
)

func printBanner() {
	banner := `
░█▀▀░█▀▄░▀█▀░█▄█░█▀█░█▀█
░█░░░█▀▄░░█░░█░█░█░█░█░█
░▀▀▀░▀░▀░░▀░░▀░▀░▀▀▀░▀░▀

monitor your targets, hunt fresh assets in real time!
`
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#cfff4aff")).Render(banner))
}
