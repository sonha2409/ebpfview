<p align="center">
  <h1 align="center">ebpfview</h1>
  <p align="center">Zero-instrumentation observability for Linux, powered by eBPF.</p>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#building-from-source">Building</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#license">License</a>
</p>

<p align="center">
  <a href="https://github.com/sonhathai/ebpfview/actions"><img src="https://github.com/sonhathai/ebpfview/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/sonhathai/ebpfview/releases"><img src="https://img.shields.io/github/v/release/sonhathai/ebpfview" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/sonhathai/ebpfview"><img src="https://goreportcard.com/badge/github.com/sonhathai/ebpfview" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

---

**ebpfview** is a single-binary CLI and live TUI that attaches eBPF programs to a running Linux system and streams real-time network flows, syscall latency heatmaps, per-process CPU profiling, flamegraph data, and userspace function traces — with zero changes to your applications.

```
┌───────────────────────────────────────────────────────────────┐
│ [1:Overview]  2:Flows  3:Trace  4:CPU  5:Flame  6:Probes     │
├──────────────────────────────┬────────────────────────────────┤
│ Top Flows                    │ CPU Breakdown                  │
│ 10.0.1.5:443  → 10.0.2.3    │ ████████░░ nginx     42%      │
│ 10.0.1.5:8080 → 10.0.2.9    │ █████░░░░░ postgres  28%      │
│ 10.0.1.5:3000 → 10.0.2.7    │ ███░░░░░░░ node      15%      │
│ fd::1:6379    → fd::1:9090   │ ██░░░░░░░░ envoy      9%      │
├──────────────────────────────┴────────────────────────────────┤
│ Probes: ●flows ●trace ●cpu ○flame   Overhead: 0.3%  Drops: 0 │
└───────────────────────────────────────────────────────────────┘
```

## Features

### Live Network Flows

Streams network flows in real time using XDP/TC hooks. Shows source/destination, protocol, bytes/sec, packet rate, and estimated RTT — no tcpdump required.

- **TLS-aware**: Auto-discovers OpenSSL/BoringSSL/GnuTLS via `/proc/<pid>/maps` and attaches uprobes to correlate plaintext throughput with encrypted wire bytes. Extracts TLS version and SNI.
- **Network namespace aware**: Attaches BPF programs per-netns for full pod-to-pod visibility on Kubernetes nodes.

### Syscall Latency Tracing

Attaches kprobes to a process's syscalls and outputs per-syscall latency histograms. Instantly diagnose `read()` spikes or `futex` contention without touching the application.

- Log2 histogram buckets aggregated in-kernel for minimal overhead
- Unicode block heatmap rendering in the TUI (time vs. latency vs. intensity)

### Per-Process CPU Profiling

An htop-like live view built on perf events, showing per-process CPU time broken down by kernel vs. userspace, context switch rates, and on-CPU/off-CPU ratios.

### Flamegraphs

Samples stack traces via perf events and emits flamegraphs in multiple formats:

```bash
ebpfview flamegraph <pid> --format html    # Interactive d3.js viewer (default)
ebpfview flamegraph <pid> --format pprof   # Compatible with go tool pprof / Parca
ebpfview flamegraph <pid> --format svg     # Static Brendan Gregg-style SVG
ebpfview flamegraph <pid> --format folded  # Gregg folded stack format
```

- **Full DWARF unwinding** for both kernel and userspace stacks — handles optimized binaries where frame pointers are stripped
- Falls back to ORC (kernel) and frame pointers gracefully, with a quality indicator per stack

### Userspace Function Tracing

Language-aware uprobe presets with auto-detection:

| Runtime | Presets |
|---------|---------|
| **Go** | HTTP handler latency, goroutine creation, GC pauses, channel ops |
| **Python** | Function call/return, GIL acquire/release |
| **Java** | GC, JIT compilation, thread lifecycle (via USDT) |
| **Node.js** | V8 USDT probes, HTTP request handling |

Manual mode for arbitrary functions: `ebpfview uprobe -p <pid> -f 'malloc,free,custom_func'`

### Unified Dashboard

A hybrid tabbed + split-pane TUI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea):

- **Tabs**: Overview, Flows, Trace, CPU, Flamegraph, Probes
- **Visualization**: Braille-dot sparklines, Unicode heatmaps, in-terminal flamegraphs
- **Interaction**: Mouse support, vim keybindings (hjkl, /, :), click-to-drill-down
- **Composable**: Toggle probes on/off live without restarting — hot-loads BPF programs on demand

### Daemon Mode (`ebpfviewd`)

A separate privileged daemon for continuous monitoring with zero-gap restarts:

- **Privilege separation**: Daemon runs as root (or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`), CLI connects unprivileged via Unix socket
- **BPF pinning**: Programs and maps pinned to `/sys/fs/bpf/ebpfview/` — survives daemon restarts with no event loss
- **Export**: Prometheus `/metrics` endpoint with cardinality controls, OTLP (gRPC/HTTP) for Grafana/Jaeger/Datadog, JSON streaming
- **Configuration**: CLI flags with TOML fallback (`/etc/ebpfview/config.toml`)

### Kubernetes Native

Resolves PIDs to pod names and namespaces automatically:

```
PID → /proc/<pid>/cgroup → container ID → containerd/CRI-O → kubelet API → pod/namespace
```

Pod metadata appears as columns in every view. Deploy as a DaemonSet via the included Helm chart.

### Self-Monitoring

ebpfview tracks its own overhead and won't degrade the system it's observing:

- Monitors BPF program run time, ring buffer fill rate, and userspace CPU consumption
- Configurable overhead budget (default: 1% CPU)
- Auto-disables probes if the threshold is breached
- Overhead metrics visible in the TUI status bar and exposed via Prometheus

### Runtime Feature Detection (CO-RE)

Probes for kernel capabilities at startup and degrades gracefully:

| Feature | Minimum Kernel | Fallback |
|---------|---------------|----------|
| Ring buffers | 5.8 | Perf buffers |
| BPF trampolines (fentry/fexit) | 5.5 | kprobe/kretprobe |
| BTF / CO-RE | 5.2 | Embedded btfhub archive |
| DWARF stack walking | 5.15 | Frame pointers |
| XDP | varies by driver | TC hooks |

No recompilation needed across kernel versions.

## Quick Start

```bash
# Install
brew install sonhathai/tap/ebpfview   # macOS (for remote targets)
curl -sSL https://get.ebpfview.dev | sh  # Linux

# Launch the dashboard (requires root or CAP_BPF)
sudo ebpfview

# Or use individual commands
sudo ebpfview flows                       # Live network flow table
sudo ebpfview trace nginx                 # Syscall latency for nginx
sudo ebpfview top                         # Per-process CPU profiling
sudo ebpfview flamegraph <pid>            # Generate flamegraph
sudo ebpfview uprobe -p <pid> --preset go # Go runtime tracing
```

## Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/sonhathai/ebpfview/releases). Available for `linux/amd64` and `linux/arm64`.

### Homebrew

```bash
brew tap sonhathai/tap
brew install ebpfview
```

### AUR (Arch Linux)

```bash
yay -S ebpfview-bin   # pre-built binary
yay -S ebpfview       # build from source
```

### Debian / Ubuntu

```bash
curl -sSL https://github.com/sonhathai/ebpfview/releases/latest/download/ebpfview_amd64.deb -o ebpfview.deb
sudo dpkg -i ebpfview.deb
```

### RHEL / Fedora

```bash
sudo rpm -i https://github.com/sonhathai/ebpfview/releases/latest/download/ebpfview_amd64.rpm
```

### Container Image

```bash
docker run --rm --privileged \
  -v /sys/kernel:/sys/kernel:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/sonhathai/ebpfview
```

### Kubernetes (Helm)

```bash
helm repo add ebpfview https://sonhathai.github.io/ebpfview
helm install ebpfview ebpfview/ebpfview
```

## Usage

### Unified Dashboard

```bash
sudo ebpfview
```

Navigate between tabs with number keys (`1`-`6`) or `Tab`. Toggle probes on/off with `p`. Press `?` for help.

### Network Flows

```bash
sudo ebpfview flows                    # All flows
sudo ebpfview flows --tls              # TLS-aware mode (auto-discovers SSL libraries)
sudo ebpfview flows --namespace <ns>   # Filter by network namespace
sudo ebpfview flows --output json      # JSON streaming for scripting
```

### Syscall Tracing

```bash
sudo ebpfview trace <pid>              # Trace by PID
sudo ebpfview trace nginx              # Trace by process name
sudo ebpfview trace <pid> --syscall read,write  # Filter specific syscalls
```

### CPU Profiling

```bash
sudo ebpfview top                      # All processes
sudo ebpfview top --sort kernel        # Sort by kernel time
```

### Flamegraphs

```bash
sudo ebpfview flamegraph <pid>                    # Interactive HTML (default)
sudo ebpfview flamegraph <pid> --format pprof     # For go tool pprof
sudo ebpfview flamegraph <pid> --duration 30s     # Sample for 30 seconds
sudo ebpfview flamegraph <pid> --freq 199         # Custom sampling frequency
```

### Userspace Tracing

```bash
sudo ebpfview uprobe -p <pid> --preset go         # Go runtime presets
sudo ebpfview uprobe -p <pid> --preset python      # Python presets
sudo ebpfview uprobe -p <pid> -f 'malloc,free'     # Manual function tracing
sudo ebpfview uprobe -p <pid> --list-usdt          # List available USDT probes
```

### Daemon Mode

```bash
# Start the daemon
sudo systemctl start ebpfviewd

# Query without sudo
ebpfview flows
ebpfview top

# Configure
sudo vim /etc/ebpfview/config.toml
```

### Prometheus Integration

```bash
# Daemon exposes metrics
curl http://localhost:9090/metrics

# Or run standalone
sudo ebpfview --prometheus :9090
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  CLI / TUI / Export                                 │
│  cobra commands, bubbletea, Prometheus, OTLP, JSON  │
├─────────────────────────────────────────────────────┤
│  Go Userspace Agent                                 │
│  loader ─→ pipeline ─→ tui / export                 │
│  feature detection, container resolution, monitor   │
├─────────────────────────────────────────────────────┤
│  Linux Kernel (eBPF)                                │
│  kprobes, XDP/TC, perf events, uprobe/USDT          │
│  ring buffers, BPF maps, BTF/CO-RE                  │
└─────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Pure Go** — no CGo. Uses [cilium/ebpf](https://github.com/cilium/ebpf) for BPF loading and map access.
- **CO-RE (Compile Once, Run Everywhere)** — BPF programs use BTF for portable struct access across kernel versions. No recompilation needed.
- **Kernel-side aggregation** — Histograms, counters, and flow tables are computed in BPF maps. Userspace polls aggregated data on a configurable interval. Ring buffers reserved for low-frequency events and raw mode (`--raw`).
- **Adaptive back-pressure** — In raw mode, dynamically adjusts sampling rate based on ring buffer fill level. Drop counter always visible.
- **Hot-loading** — Each probe type is an independent BPF program. Load/unload without affecting other running probes.

## Building from Source

### Prerequisites

- Go 1.22+
- Clang/LLVM 15+ (for BPF compilation)
- Linux headers (for BPF development)
- [Nix](https://nixos.org/download.html) (recommended — provides all dependencies)

### With Nix (recommended)

```bash
nix develop          # Enter dev shell with all dependencies
make generate        # Compile BPF C → Go bindings
make build           # Build ebpfview and ebpfviewd
make test            # Run unit tests
make test-bpf        # Run BPF integration tests (requires Linux VM)
make lint            # golangci-lint + clang-tidy
```

### Without Nix

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Build
make generate
make build
```

### Running Tests

```bash
make test            # Unit tests (no root, no Linux required)
make test-bpf        # BPF integration tests in QEMU microVM
```

## Requirements

- **Linux kernel 5.4+** (5.8+ recommended for full feature set)
- **Root or capabilities**: `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN` (or run the daemon)
- **BTF enabled** (most modern distros): check with `ls /sys/kernel/btf/vmlinux`
- Supported architectures: `amd64`, `arm64`

## Comparison

| Feature | ebpfview | bpftrace | Inspektor Gadget | Pixie |
|---------|----------|----------|-----------------|-------|
| Single binary | Yes | Yes | No (k8s operator) | No (k8s operator) |
| Live TUI | Yes | No | Partial | Web UI |
| Network flows | Yes (XDP/TC) | Manual | Yes | Yes |
| Syscall latency | Yes | Manual | Yes | Yes |
| Flamegraphs | Yes (DWARF) | Manual | No | Yes |
| TLS inspection | Yes (auto) | Manual | No | Yes |
| Uprobe presets | Yes | No | No | Yes |
| Daemon mode | Yes | No | Yes | Yes |
| Zero-gap restart | Yes | N/A | No | No |
| No k8s required | Yes | Yes | No | No |
| Runtime detection | Yes | Partial | No | No |
| Self-monitoring | Yes | No | No | No |

## Contributing

Contributions are welcome. Please read the [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

```bash
# Development workflow
nix develop                  # Enter dev shell
make generate && make build  # Build
make test                    # Test
make lint                    # Lint
```

## License

[Apache License 2.0](LICENSE)

---

<p align="center">
  Built with <a href="https://github.com/cilium/ebpf">cilium/ebpf</a>, <a href="https://github.com/charmbracelet/bubbletea">Bubble Tea</a>, and a lot of kernel headers.
</p>
