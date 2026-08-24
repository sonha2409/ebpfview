package cpu

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProc creates a fake /proc root containing one entry per pid→comm
// pair and returns its path.
func fakeProc(t *testing.T, procs map[uint32]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, comm := range procs {
		dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func Test_CommReader_ReadsAndTrims(t *testing.T) {
	root := fakeProc(t, map[uint32]string{123: "nginx"})
	c := newCommReader(root)

	if got := c.comm(123); got != "nginx" {
		t.Errorf("comm(123) = %q, want %q", got, "nginx")
	}
}

func Test_CommReader_FallsBackToCacheAfterExit(t *testing.T) {
	root := fakeProc(t, map[uint32]string{123: "nginx"})
	c := newCommReader(root)
	c.comm(123) // populate cache

	if err := os.RemoveAll(filepath.Join(root, "123")); err != nil {
		t.Fatal(err)
	}

	if got := c.comm(123); got != "nginx" {
		t.Errorf("comm(123) after exit = %q, want cached %q", got, "nginx")
	}
}

func Test_CommReader_UnknownPidUsesPlaceholder(t *testing.T) {
	c := newCommReader(fakeProc(t, nil))

	if got := c.comm(999); got != "pid_999" {
		t.Errorf("comm(999) = %q, want %q", got, "pid_999")
	}
}

func Test_CommReader_Alive(t *testing.T) {
	root := fakeProc(t, map[uint32]string{123: "nginx"})
	c := newCommReader(root)

	if !c.alive(123) {
		t.Error("alive(123) = false, want true")
	}
	if c.alive(456) {
		t.Error("alive(456) = true, want false")
	}
}

func Test_CommReader_SanitizesUntrustedComm(t *testing.T) {
	tests := []struct {
		name string
		comm string
		want string
	}{
		{
			name: "ansi escape sequence",
			comm: "\x1b[2Jevil",
			want: "?[2Jevil",
		},
		{
			name: "control characters",
			comm: "a\tb\rc\x00d",
			want: "a?b?c?d",
		},
		{
			name: "del character",
			comm: "x\x7fy",
			want: "x?y",
		},
		{
			name: "invalid utf-8 byte",
			comm: "a\xffb",
			want: "a?b",
		},
		{
			name: "clean name untouched",
			comm: "nginx-worker",
			want: "nginx-worker",
		},
		{
			name: "overlong name truncated to 16",
			comm: "abcdefghijklmnopqrstuvwxyz",
			want: "abcdefghijklmnop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fakeProc(t, map[uint32]string{42: tt.comm})
			c := newCommReader(root)
			if got := c.comm(42); got != tt.want {
				t.Errorf("comm(42) = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_CommReader_ForgetDropsCache(t *testing.T) {
	root := fakeProc(t, map[uint32]string{123: "nginx"})
	c := newCommReader(root)
	c.comm(123)

	if err := os.RemoveAll(filepath.Join(root, "123")); err != nil {
		t.Fatal(err)
	}
	c.forget(123)

	if got := c.comm(123); got != "pid_123" {
		t.Errorf("comm(123) after forget = %q, want %q", got, "pid_123")
	}
}
