//go:build !linux

package syscalls

// syscallNames is empty on non-Linux platforms; SyscallName falls
// through to the "syscall_<nr>" format. This lets unit tests that
// exercise aggregation logic run on macOS dev machines.
var syscallNames = map[uint32]string{}
