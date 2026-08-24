package cpu

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	name := strings.TrimSpace(string(raw))
	if name == "" {
		name = fmt.Sprintf("pid_%d", pid)
	}
	c.cache[pid] = name
	return name
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
