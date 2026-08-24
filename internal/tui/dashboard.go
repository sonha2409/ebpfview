// Package tui implements the unified dashboard: pure bubbletea models fed
// by pipeline channels. No BPF or system access happens here.
package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Minimum terminal size below which the dashboard renders a hint instead
// of attempting a layout.
const (
	minWidth  = 40
	minHeight = 10
)

// Tab is one dashboard view. A Tab's Update must return a model that still
// implements Tab. Placeholder tabs fill all slots until 5.2-5.6 replace
// them with real views.
type Tab interface {
	tea.Model
	Title() string
}

// Dashboard is the root model: it owns the tab bar, handles global keys,
// and routes every other message to the tabs.
type Dashboard struct {
	tabs   []Tab
	active int
	width  int
	height int
}

// NewDashboard returns a Dashboard showing the first tab. tabs must be
// non-empty; index i is bound to number key i+1.
func NewDashboard(tabs []Tab) Dashboard {
	return Dashboard{tabs: tabs}
}

// DefaultTabs returns the six dashboard tabs in number-key order.
func DefaultTabs() []Tab {
	return []Tab{
		newPlaceholderTab("Overview", "5.2"),
		newPlaceholderTab("Flows", "5.3"),
		newPlaceholderTab("Trace", "5.4"),
		newPlaceholderTab("CPU", "5.5"),
		newPlaceholderTab("Flamegraph", "6.9"),
		newPlaceholderTab("Probes", "5.6"),
	}
}

func (d Dashboard) Init() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(d.tabs))
	for _, t := range d.tabs {
		if cmd := t.Init(); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return tea.Batch(cmds...)
}

func (d Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return d.handleKey(msg)
	case tea.WindowSizeMsg:
		d.width, d.height = msg.Width, msg.Height
		// Broadcast to every tab (minus the tab bar row) so background
		// tabs are laid out correctly the moment they become active.
		content := tea.WindowSizeMsg{Width: msg.Width, Height: msg.Height - tabBarHeight}
		cmds := make([]tea.Cmd, 0, len(d.tabs))
		for i := range d.tabs {
			m, cmd := d.tabs[i].Update(content)
			d.tabs[i] = m.(Tab)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return d, tea.Batch(cmds...)
	}
	return d.updateActive(msg)
}

// handleKey consumes global navigation keys; anything else goes to the
// active tab. All key routing lives here so a future focus/capture mode
// (5.8 search) only changes this method.
func (d Dashboard) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key := msg.String(); key {
	case "q", "ctrl+c":
		return d, tea.Quit
	case "tab":
		d.active = (d.active + 1) % len(d.tabs)
		return d, nil
	case "shift+tab":
		d.active = (d.active - 1 + len(d.tabs)) % len(d.tabs)
		return d, nil
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
		if i := int(key[0] - '1'); i >= 0 && i < len(d.tabs) {
			d.active = i
		}
		return d, nil
	}
	return d.updateActive(msg)
}

func (d Dashboard) updateActive(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, cmd := d.tabs[d.active].Update(msg)
	d.tabs[d.active] = m.(Tab)
	return d, cmd
}

func (d Dashboard) View() string {
	if d.width == 0 || d.height == 0 {
		return "" // nothing sane to draw before the first WindowSizeMsg
	}
	if d.width < minWidth || d.height < minHeight {
		return fmt.Sprintf("terminal too small (need at least %dx%d)", minWidth, minHeight)
	}
	return lipgloss.JoinVertical(lipgloss.Left, d.tabBar(), d.tabs[d.active].View())
}

func (d Dashboard) tabBar() string {
	items := make([]string, len(d.tabs))
	for i, t := range d.tabs {
		label := fmt.Sprintf("%d:%s", i+1, t.Title())
		if i == d.active {
			items[i] = activeTabStyle.Render("[" + label + "]")
		} else {
			items[i] = inactiveTabStyle.Render(" " + label + " ")
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, items...)
}

// Run starts the dashboard and blocks until the user quits or ctx is
// canceled. External cancellation is a clean shutdown, not an error.
func Run(ctx context.Context, tabs []Tab) error {
	p := tea.NewProgram(NewDashboard(tabs), tea.WithAltScreen(), tea.WithContext(ctx))
	if _, err := p.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("tui.Run: %w", err)
	}
	return nil
}
