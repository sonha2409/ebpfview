package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// placeholderTab fills a dashboard slot until the real view ships.
type placeholderTab struct {
	title  string
	item   string // SPEC.md feature item that replaces it, e.g. "5.2"
	width  int
	height int
}

func newPlaceholderTab(title, item string) *placeholderTab {
	return &placeholderTab{title: title, item: item}
}

func (p *placeholderTab) Title() string { return p.title }

func (p *placeholderTab) Init() tea.Cmd { return nil }

func (p *placeholderTab) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := msg.(tea.WindowSizeMsg); ok {
		p.width, p.height = size.Width, size.Height
	}
	return p, nil
}

func (p *placeholderTab) View() string {
	body := placeholderStyle.Render(fmt.Sprintf("%s — available in %s", p.title, p.item))
	return lipgloss.Place(p.width, p.height, lipgloss.Center, lipgloss.Center, body)
}
