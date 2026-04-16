package netns

import "testing"

func Test_Handle_String(t *testing.T) {
	tests := []struct {
		h    Handle
		want string
	}{
		{Handle{Inode: 42, Name: "blue"}, "netns(blue, inode=42)"},
		{Handle{Inode: 17}, "netns(inode=17)"},
	}
	for _, tt := range tests {
		if got := tt.h.String(); got != tt.want {
			t.Errorf("Handle.String() = %q, want %q", got, tt.want)
		}
	}
}

func Test_EventType_String(t *testing.T) {
	tests := []struct {
		e    EventType
		want string
	}{
		{EventAdded, "added"},
		{EventRemoved, "removed"},
		{EventType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.e.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.e, got, tt.want)
		}
	}
}
