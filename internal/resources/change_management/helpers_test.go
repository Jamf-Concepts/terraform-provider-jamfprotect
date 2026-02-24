package change_management

import (
	"errors"
	"testing"
)

// TestIsChangeFreezeNotActiveError_MatchingError verifies that an error containing the expected message returns true.
func TestIsChangeFreezeNotActiveError_MatchingError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "exact phrase",
			err:  errors.New("is not in a change freeze"),
		},
		{
			name: "phrase with surrounding text",
			err:  errors.New("organization is not in a change freeze currently"),
		},
		{
			name: "phrase at end of message",
			err:  errors.New("the tenant is not in a change freeze"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !isChangeFreezeNotActiveError(tt.err) {
				t.Errorf("expected true for error %q", tt.err)
			}
		})
	}
}

// TestIsChangeFreezeNotActiveError_NonMatchingError verifies that errors without the expected message return false.
func TestIsChangeFreezeNotActiveError_NonMatchingError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "different error message",
			err:  errors.New("something went wrong"),
		},
		{
			name: "partial match",
			err:  errors.New("is not in a change"),
		},
		{
			name: "empty error message",
			err:  errors.New(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if isChangeFreezeNotActiveError(tt.err) {
				t.Errorf("expected false for error %q", tt.err)
			}
		})
	}
}

// TestIsChangeFreezeNotActiveError_NilError verifies that a nil error returns false.
func TestIsChangeFreezeNotActiveError_NilError(t *testing.T) {
	t.Parallel()

	if isChangeFreezeNotActiveError(nil) {
		t.Error("expected false for nil error")
	}
}
