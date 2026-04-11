package loader

import "errors"

var (
	// ErrNotFound is returned when a handle ID is not found in the manager.
	ErrNotFound = errors.New("handle not found")

	// ErrAlreadyDetached is returned when detaching a handle that is already detached.
	ErrAlreadyDetached = errors.New("handle already detached")

	// ErrNotSupported is returned when a required kernel feature is unavailable.
	ErrNotSupported = errors.New("feature not supported by kernel")

	// ErrVerifierReject is returned when the BPF verifier rejects a program.
	ErrVerifierReject = errors.New("BPF verifier rejected program")

	// ErrMapNotFound is returned when a map name is not found in the collection.
	ErrMapNotFound = errors.New("map not found in collection")

	// ErrProgNotFound is returned when a program name is not found in the collection.
	ErrProgNotFound = errors.New("program not found in collection")

	// ErrNotAttached is returned when trying to read from a handle that has no attachments.
	ErrNotAttached = errors.New("handle not attached")
)
