package feature

import (
	"log/slog"
	"testing"
)

func Test_Level_String(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{Unavailable, "unavailable"},
		{Available, "available"},
		{Level(99), "unavailable"}, // unknown defaults to unavailable
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func Test_Features_Log_does_not_panic(t *testing.T) {
	// Logging a zero-value Features should not panic.
	f := &Features{KernelVersion: "5.15.0-test"}
	f.Log(slog.Default())
}
