package loader

import (
	"testing"
)

func Test_HelloProbe_Close_nil(t *testing.T) {
	// Closing a HelloProbe with nil fields should not panic.
	h := &HelloProbe{}
	if err := h.Close(); err != nil {
		t.Fatalf("Close on empty HelloProbe: %v", err)
	}
}
