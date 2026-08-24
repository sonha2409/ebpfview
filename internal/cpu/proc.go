package cpu

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// commReader resolves PIDs to process names via <root>/<pid>/comm and
// checks process liveness via <root>/<pid>. root is /proc in production
// and a fixture directory in tests. Names are cached so a process that
// exits mid-interval still gets its last known name in the final Record.
type commReader struct {
	root  string
	cache map[uint32]string
}

func newCommReader(root string) *commReader {
	return &commReader{
		root:  root,
		cache: make(map[uint32]string),
	}
}

// comm returns the process name for pid. Falls back to the cached name
// when the process is gone, and to "pid_<n>" when it was never seen.
func (c *commReader) comm(pid uint32) string {
	raw, err := os.ReadFile(filepath.Join(c.root, strconv.FormatUint(uint64(pid), 10), "comm"))
	if err != nil {
		if cached, ok := c.cache[pid]; ok {
			return cached
		}
		return fmt.Sprintf("pid_%d", pid)
	}
	name := sanitizeComm(strings.TrimSpace(string(raw)))
	if name == "" {
		name = fmt.Sprintf("pid_%d", pid)
	}
	c.cache[pid] = name
	return name
}

// maxCommLen bounds sanitized names. The kernel caps comm at 15 bytes
// (TASK_COMM_LEN - 1); anything longer means the data source is not a
// real procfs and gets truncated rather than trusted.
const maxCommLen = 16

// sanitizeComm neutralizes untrusted process names before they reach a
// terminal or UI. A process picks its own comm via prctl(PR_SET_NAME)
// and can embed ANSI escape sequences or other control bytes, so every
// control character, DEL, and invalid UTF-8 byte is replaced with '?'.
func sanitizeComm(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n == maxCommLen {
			break
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// alive reports whether pid still has a directory under root.
func (c *commReader) alive(pid uint32) bool {
	_, err := os.Stat(filepath.Join(c.root, strconv.FormatUint(uint64(pid), 10)))
	return err == nil
}

// forget drops pid from the name cache. Called after reaping so a
// recycled PID does not inherit the previous process's name.
func (c *commReader) forget(pid uint32) {
	delete(c.cache, pid)
}
