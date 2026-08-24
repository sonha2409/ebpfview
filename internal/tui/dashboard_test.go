package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// spyTab records every message it receives.
type spyTab struct {
	title string
	msgs  []tea.Msg
}

func (s *spyTab) Title() string { return s.title }
func (s *spyTab) Init() tea.Cmd { return nil }
func (s *spyTab) View() string  { return s.title }
func (s *spyTab) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	s.msgs = append(s.msgs, msg)
	return s, nil
}

func spyTabs(n int) []Tab {
	tabs := make([]Tab, n)
	for i := range tabs {
		tabs[i] = &spyTab{title: string(rune('A' + i))}
	}
	return tabs
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func update(t *testing.T, d Dashboard, msg tea.Msg) (Dashboard, tea.Cmd) {
	t.Helper()
	m, cmd := d.Update(msg)
	next, ok := m.(Dashboard)
	if !ok {
		t.Fatalf("Update returned %T, want Dashboard", m)
	}
	return next, cmd
}

func Test_Dashboard_SwitchesTabByNumber(t *testing.T) {
	tests := []struct {
		name  string
		start int
		key   string
		want  int
	}{
		{"key 1 selects first tab", 2, "1", 0},
		{"key 3 selects third tab", 0, "3", 2},
		{"key 6 selects last tab", 0, "6", 5},
		{"key 7 out of range ignored", 2, "7", 2},
		{"key 0 out of range ignored", 2, "0", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDashboard(spyTabs(6))
			d.active = tt.start

			d, _ = update(t, d, keyMsg(tt.key))

			if d.active != tt.want {
				t.Fatalf("active = %d, want %d", d.active, tt.want)
			}
		})
	}
}

func Test_Dashboard_CyclesTabsWithTab(t *testing.T) {
	tests := []struct {
		name  string
		start int
		key   string
		want  int
	}{
		{"tab advances", 0, "tab", 1},
		{"tab wraps at end", 2, "tab", 0},
		{"shift+tab goes back", 1, "shift+tab", 0},
		{"shift+tab wraps at start", 0, "shift+tab", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDashboard(spyTabs(3))
			d.active = tt.start

			d, _ = update(t, d, keyMsg(tt.key))

			if d.active != tt.want {
				t.Fatalf("active = %d, want %d", d.active, tt.want)
			}
		})
	}
}

func Test_Dashboard_QuitKeys(t *testing.T) {
	for _, key := range []string{"q", "ctrl+c"} {
		t.Run(key, func(t *testing.T) {
			d := NewDashboard(spyTabs(2))

			_, cmd := update(t, d, keyMsg(key))

			if cmd == nil {
				t.Fatal("cmd = nil, want tea.Quit")
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Fatalf("cmd() = %T, want tea.QuitMsg", cmd())
			}
		})
	}
}

func Test_Dashboard_BroadcastsWindowSize(t *testing.T) {
	tabs := spyTabs(3)
	d := NewDashboard(tabs)

	d, _ = update(t, d, tea.WindowSizeMsg{Width: 100, Height: 40})

	want := tea.WindowSizeMsg{Width: 100, Height: 40 - tabBarHeight}
	for i, tab := range tabs {
		spy := tab.(*spyTab)
		if len(spy.msgs) != 1 {
			t.Fatalf("tab %d received %d msgs, want 1", i, len(spy.msgs))
		}
		if spy.msgs[0] != want {
			t.Fatalf("tab %d received %v, want %v", i, spy.msgs[0], want)
		}
	}
	if d.width != 100 || d.height != 40 {
		t.Fatalf("dashboard size = %dx%d, want 100x40", d.width, d.height)
	}
}

func Test_Dashboard_DelegatesToActiveTab(t *testing.T) {
	type customMsg struct{}
	tabs := spyTabs(2)
	d := NewDashboard(tabs)
	d.active = 1

	_, _ = update(t, d, customMsg{})

	if got := len(tabs[0].(*spyTab).msgs); got != 0 {
		t.Fatalf("inactive tab received %d msgs, want 0", got)
	}
	active := tabs[1].(*spyTab)
	if len(active.msgs) != 1 {
		t.Fatalf("active tab received %d msgs, want 1", len(active.msgs))
	}
	if _, ok := active.msgs[0].(customMsg); !ok {
		t.Fatalf("active tab received %T, want customMsg", active.msgs[0])
	}
}

func Test_Dashboard_NavigationKeysNotDelegated(t *testing.T) {
	tabs := spyTabs(3)
	d := NewDashboard(tabs)

	for _, key := range []string{"2", "tab", "shift+tab", "9"} {
		d, _ = update(t, d, keyMsg(key))
	}

	for i, tab := range tabs {
		if got := len(tab.(*spyTab).msgs); got != 0 {
			t.Fatalf("tab %d received %d msgs, want 0", i, got)
		}
	}
}

func Test_Dashboard_ViewBeforeFirstResize(t *testing.T) {
	d := NewDashboard(spyTabs(2))

	if got := d.View(); got != "" {
		t.Fatalf("View() = %q, want empty before first WindowSizeMsg", got)
	}
}

func Test_Dashboard_ViewTooSmall(t *testing.T) {
	tests := []struct {
		name          string
		width, height int
	}{
		{"too narrow", minWidth - 1, 50},
		{"too short", 100, minHeight - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDashboard(spyTabs(2))

			d, _ = update(t, d, tea.WindowSizeMsg{Width: tt.width, Height: tt.height})

			if got := d.View(); !strings.Contains(got, "terminal too small") {
				t.Fatalf("View() = %q, want minimum-size message", got)
			}
		})
	}
}

func Test_Dashboard_ViewShowsActiveTab(t *testing.T) {
	d := NewDashboard(spyTabs(3))
	d.active = 1
	d, _ = update(t, d, tea.WindowSizeMsg{Width: 80, Height: 24})

	got := d.View()

	if !strings.Contains(got, "2:B") {
		t.Fatalf("View() = %q, want tab bar containing %q", got, "2:B")
	}
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) < 2 || !strings.Contains(lines[1], "B") {
		t.Fatalf("View() = %q, want active tab content %q below tab bar", got, "B")
	}
}
