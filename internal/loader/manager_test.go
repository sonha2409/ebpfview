package loader

import (
	"log/slog"
	"testing"

	"github.com/sonhathai/ebpfview/internal/feature"
)

func Test_NewManager(t *testing.T) {
	f := &feature.Features{KernelVersion: "5.15.0-test"}
	mgr := NewManager(f, slog.Default())

	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.Features() != f {
		t.Error("Features() returned different pointer")
	}
}

func Test_Manager_Close_empty(t *testing.T) {
	f := &feature.Features{}
	mgr := NewManager(f, slog.Default())

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close on empty manager: %v", err)
	}
}

func Test_Manager_Handle_not_found(t *testing.T) {
	f := &feature.Features{}
	mgr := NewManager(f, slog.Default())

	_, ok := mgr.Handle(999)
	if ok {
		t.Error("Handle(999) should return false on empty manager")
	}
}
