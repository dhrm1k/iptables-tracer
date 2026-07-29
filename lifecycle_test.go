package main

import (
	"errors"
	"testing"
)

func TestWithCleanup(t *testing.T) {
	runErr := errors.New("run failed")
	cleanupErr := errors.New("cleanup failed")

	tests := []struct {
		name           string
		runErr         error
		cleanupErr     error
		wantRunErr     bool
		wantCleanupErr bool
	}{
		{name: "success"},
		{name: "run error still cleans up", runErr: runErr, wantRunErr: true},
		{name: "cleanup error is returned", cleanupErr: cleanupErr, wantCleanupErr: true},
		{name: "both errors are returned", runErr: runErr, cleanupErr: cleanupErr, wantRunErr: true, wantCleanupErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanupCalled := false
			got := withCleanup(
				func() error { return test.runErr },
				func() error {
					cleanupCalled = true
					return test.cleanupErr
				},
			)

			if !cleanupCalled {
				t.Fatal("cleanup was not called")
			}
			if errors.Is(got, runErr) != test.wantRunErr {
				t.Errorf("errors.Is(result, runErr) = %v, expected %v", errors.Is(got, runErr), test.wantRunErr)
			}
			if errors.Is(got, cleanupErr) != test.wantCleanupErr {
				t.Errorf("errors.Is(result, cleanupErr) = %v, expected %v", errors.Is(got, cleanupErr), test.wantCleanupErr)
			}
		})
	}
}
