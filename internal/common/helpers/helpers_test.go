// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
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
			err:      fmt.Errorf("%w: %w: resource not found", client.ErrNotFound, client.ErrGraphQL),
			expected: true,
		},
		{
			name:     "ErrNotFound alone",
			err:      client.ErrNotFound,
			expected: true,
		},
		{
			name:     "ErrNotFound wrapped",
			err:      fmt.Errorf("wrapped: %w", client.ErrNotFound),
			expected: true,
		},
		{
			name:     "client other error",
			err:      fmt.Errorf("%w: internal server error", client.ErrGraphQL),
			expected: false,
		},
		{
			name:     "auth error",
			err:      fmt.Errorf("%w: bad credentials", client.ErrAuthentication),
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
