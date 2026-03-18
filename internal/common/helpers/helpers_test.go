// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

func TestListToStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		list     types.List
		expected []string
	}{
		{
			name:     "populated list",
			list:     StringsToList([]string{"a", "b", "c"}),
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty list",
			list:     StringsToList([]string{}),
			expected: []string{},
		},
		{
			name:     "nil input produces empty list",
			list:     StringsToList(nil),
			expected: []string{},
		},
		{
			name:     "null list",
			list:     types.ListNull(types.StringType),
			expected: []string{},
		},
		{
			name:     "unknown list",
			list:     types.ListUnknown(types.StringType),
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			result := ListToStrings(context.Background(), tc.list, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}

			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d elements, got %d", len(tc.expected), len(result))
			}
			for i, v := range tc.expected {
				if result[i] != v {
					t.Errorf("element %d: expected %q, got %q", i, v, result[i])
				}
			}
		})
	}
}

func TestStringsToList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		wantLen  int
		wantNull bool
	}{
		{
			name:    "populated",
			input:   []string{"x", "y"},
			wantLen: 2,
		},
		{
			name:    "empty",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "nil produces empty list",
			input:   nil,
			wantLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := StringsToList(tc.input)

			if result.IsNull() {
				t.Fatal("expected non-null list")
			}
			if len(result.Elements()) != tc.wantLen {
				t.Errorf("expected %d elements, got %d", tc.wantLen, len(result.Elements()))
			}
		})
	}
}

func TestStringsToListRoundTrip(t *testing.T) {
	t.Parallel()

	original := []string{"hello", "world", "terraform"}
	list := StringsToList(original)

	var diags diag.Diagnostics
	roundTripped := ListToStrings(context.Background(), list, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	if len(roundTripped) != len(original) {
		t.Fatalf("expected %d elements, got %d", len(original), len(roundTripped))
	}
	for i := range original {
		if roundTripped[i] != original[i] {
			t.Errorf("element %d: expected %q, got %q", i, original[i], roundTripped[i])
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrNotFound wrapped with ErrGraphQL",
			err:      fmt.Errorf("%w: %w: resource not found", jamfprotect.ErrNotFound, jamfprotect.ErrGraphQL),
			expected: true,
		},
		{
			name:     "ErrNotFound alone",
			err:      jamfprotect.ErrNotFound,
			expected: true,
		},
		{
			name:     "ErrNotFound wrapped",
			err:      fmt.Errorf("wrapped: %w", jamfprotect.ErrNotFound),
			expected: true,
		},
		{
			name:     "client other error",
			err:      fmt.Errorf("%w: internal server error", jamfprotect.ErrGraphQL),
			expected: false,
		},
		{
			name:     "auth error",
			err:      fmt.Errorf("%w: bad credentials", jamfprotect.ErrAuthentication),
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("something went wrong"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := IsNotFoundError(tc.err)
			if result != tc.expected {
				t.Errorf("IsNotFoundError(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestSetContainsUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		set      types.Set
		expected bool
	}{
		{
			name:     "known elements",
			set:      StringsToSet([]string{"a", "b"}),
			expected: false,
		},
		{
			name:     "empty set",
			set:      StringsToSet([]string{}),
			expected: false,
		},
		{
			name:     "null set",
			set:      types.SetNull(types.StringType),
			expected: false,
		},
		{
			name:     "unknown set",
			set:      types.SetUnknown(types.StringType),
			expected: true,
		},
		{
			name: "set with unknown element",
			set: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringUnknown(),
			}),
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := SetContainsUnknown(tc.set)
			if result != tc.expected {
				t.Errorf("SetContainsUnknown() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// TestIsKnownString ensures the helper flags known values correctly.
func TestIsKnownString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    types.String
		expected bool
	}{
		{
			name:     "value",
			value:    types.StringValue("hello"),
			expected: true,
		},
		{
			name:     "empty string",
			value:    types.StringValue(""),
			expected: true,
		},
		{
			name:     "null",
			value:    types.StringNull(),
			expected: false,
		},
		{
			name:     "unknown",
			value:    types.StringUnknown(),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := IsKnownString(tc.value)
			if result != tc.expected {
				t.Errorf("IsKnownString(%v) = %v, want %v", tc.value, result, tc.expected)
			}
		})
	}
}
