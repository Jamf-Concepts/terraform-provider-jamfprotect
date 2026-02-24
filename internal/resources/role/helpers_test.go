package role

import (
	"errors"
	"testing"
)

// TestIsRoleNullTimestampError_MatchingError verifies that errors containing the expected pattern return true.
func TestIsRoleNullTimestampError_MatchingError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "getRole.created variant",
			err:  errors.New("Cannot return null for non-nullable type: Role.getRole.created"),
		},
		{
			name: "getRole.updated variant",
			err:  errors.New("Cannot return null for non-nullable type: Role.getRole.updated"),
		},
		{
			name: "with surrounding text and created",
			err:  errors.New("GraphQL error: Cannot return null for non-nullable type at Role path getRole.created field"),
		},
		{
			name: "with surrounding text and updated",
			err:  errors.New("GraphQL error: Cannot return null for non-nullable type at Role path getRole.updated field"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !isRoleNullTimestampError(tt.err) {
				t.Errorf("expected true for error %q", tt.err)
			}
		})
	}
}

// TestIsRoleNullTimestampError_NonMatchingError verifies that errors without the expected pattern return false.
func TestIsRoleNullTimestampError_NonMatchingError(t *testing.T) {
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
			name: "has null type but not Role",
			err:  errors.New("Cannot return null for non-nullable type: User.getUser.created"),
		},
		{
			name: "has Role but not null type",
			err:  errors.New("Role error: getRole.created failed"),
		},
		{
			name: "has null type and Role but not getRole.created or getRole.updated",
			err:  errors.New("Cannot return null for non-nullable type: Role.getRole.name"),
		},
		{
			name: "empty error message",
			err:  errors.New(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if isRoleNullTimestampError(tt.err) {
				t.Errorf("expected false for error %q", tt.err)
			}
		})
	}
}

// TestIsRoleNullTimestampError_NilError verifies that a nil error returns false.
func TestIsRoleNullTimestampError_NilError(t *testing.T) {
	t.Parallel()

	if isRoleNullTimestampError(nil) {
		t.Error("expected false for nil error")
	}
}

// TestRolePermissionAddHiddenException_WithExceptionSets verifies that "Exception" is added when "ExceptionSet" is present.
func TestRolePermissionAddHiddenException_WithExceptionSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "ExceptionSet only",
			input:    []string{"ExceptionSet"},
			expected: []string{"ExceptionSet", "Exception"},
		},
		{
			name:     "ExceptionSet with other permissions",
			input:    []string{"Computer", "ExceptionSet", "Alert"},
			expected: []string{"Computer", "ExceptionSet", "Alert", "Exception"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rolePermissionAddHiddenException(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("rolePermissionAddHiddenException() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("rolePermissionAddHiddenException()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestRolePermissionAddHiddenException_ExceptionAlreadyPresent verifies no duplicate is added when "Exception" already exists.
func TestRolePermissionAddHiddenException_ExceptionAlreadyPresent(t *testing.T) {
	t.Parallel()

	input := []string{"ExceptionSet", "Exception", "Computer"}
	got := rolePermissionAddHiddenException(input)
	if len(got) != len(input) {
		t.Fatalf("rolePermissionAddHiddenException() returned %d elements, want %d (no duplicate)", len(got), len(input))
	}
	for i, v := range got {
		if v != input[i] {
			t.Errorf("rolePermissionAddHiddenException()[%d] = %q, want %q", i, v, input[i])
		}
	}
}

// TestRolePermissionAddHiddenException_WithoutExceptionSets verifies that the list is unchanged when "ExceptionSet" is absent.
func TestRolePermissionAddHiddenException_WithoutExceptionSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "other permissions",
			input:    []string{"Computer", "Alert"},
			expected: []string{"Computer", "Alert"},
		},
		{
			name:     "single permission",
			input:    []string{"Computer"},
			expected: []string{"Computer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rolePermissionAddHiddenException(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("rolePermissionAddHiddenException() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("rolePermissionAddHiddenException()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestRolePermissionAddHiddenException_EmptyInput verifies that an empty slice is returned unchanged.
func TestRolePermissionAddHiddenException_EmptyInput(t *testing.T) {
	t.Parallel()

	got := rolePermissionAddHiddenException([]string{})
	if len(got) != 0 {
		t.Errorf("rolePermissionAddHiddenException(empty) = %v, want empty", got)
	}
}

// TestRolePermissionAddHiddenException_NilInput verifies that a nil slice is returned unchanged.
func TestRolePermissionAddHiddenException_NilInput(t *testing.T) {
	t.Parallel()

	got := rolePermissionAddHiddenException(nil)
	if got != nil {
		t.Errorf("rolePermissionAddHiddenException(nil) = %v, want nil", got)
	}
}
