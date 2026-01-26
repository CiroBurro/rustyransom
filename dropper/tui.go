package main

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
	Uptime   time.Duration
	CpuUsage float64
	CpuTemp  float64
	GpuUsage float64
	GpuTemp  float64
	MemUsage float64
}

func initialModel() model {
	return model{
		Uptime:   0,
		CpuUsage: 0,
		CpuTemp:  0,
		GpuUsage: 0,
		GpuTemp:  0,
		MemUsage: 0,
	}
}

func (m model) Init() tea.Cmd {
	return tick()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tickMsg:

		m.Uptime = getUptime()

		m.CpuUsage = getCpuUsage()

		m.CpuTemp = getCpuTemp()

		m.GpuUsage, m.GpuTemp = 0,0

		m.MemUsage = getMemoryUsage()

		return m, tick()
	}

	return m, nil
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) View() string {
	s := "┌────────────┬────────────────────────┐\n"
	s += "│   Metric   │         Value          │\n"
	s += "├────────────┼────────────────────────┤\n"
	s += fmt.Sprintf("│ %-10s │ %-22s │\n", "Uptime", m.Uptime.Round(time.Second))
	s += fmt.Sprintf("│ %-10s │ %-22s │\n", "CPU", fmt.Sprintf("%5.1f%% | Temp %4.1f°C", m.CpuUsage, m.CpuTemp))
	s += fmt.Sprintf("│ %-10s │ %-22s │\n", "GPU", fmt.Sprintf("%5.1f%% | Temp %4.1f°C", m.GpuUsage, m.GpuTemp))
	s += fmt.Sprintf("│ %-10s │ %-22s │\n", "Memory", fmt.Sprintf("%5.1f%% used", m.MemUsage))
	s += "└────────────┴────────────────────────┘\n"
	s += "\nPress q to quit.\n"
	return s
}
