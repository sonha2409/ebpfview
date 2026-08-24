package tui

import "github.com/charmbracelet/lipgloss"

// tabBarHeight is the number of rows the tab bar consumes; it is
// subtracted from the height broadcast to tabs.
const tabBarHeight = 1

var (
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Reverse(true)
	inactiveTabStyle = lipgloss.NewStyle().Faint(true)
	placeholderStyle = lipgloss.NewStyle().Faint(true)
)
