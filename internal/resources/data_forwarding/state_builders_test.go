// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestStringPointerOrNil_ValidString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    basetypes.StringValue
		expected *string
	}{
		{
			name:     "non-empty string",
			input:    types.StringValue("hello"),
			expected: strPtr("hello"),
		},
		{
			name:     "string with surrounding whitespace",
			input:    types.StringValue("  trimmed  "),
			expected: strPtr("trimmed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stringPointerOrNil(tt.input)
			if got == nil {
				t.Fatalf("stringPointerOrNil(%v) = nil, want %q", tt.input, *tt.expected)
			}
			if *got != *tt.expected {
				t.Errorf("stringPointerOrNil(%v) = %q, want %q", tt.input, *got, *tt.expected)
			}
		})
	}
}

func TestStringPointerOrNil_ReturnsNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input basetypes.StringValue
	}{
		{
			name:  "null value",
			input: types.StringNull(),
		},
		{
			name:  "unknown value",
			input: types.StringUnknown(),
		},
		{
			name:  "empty string",
			input: types.StringValue(""),
		},
		{
			name:  "whitespace only",
			input: types.StringValue("   "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stringPointerOrNil(tt.input)
			if got != nil {
				t.Errorf("stringPointerOrNil(%v) = %q, want nil", tt.input, *got)
			}
		})
	}
}

func TestStringPointerValueOrNull_ValidPointer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *string
		expected attr.Value
	}{
		{
			name:     "non-empty string pointer",
			input:    strPtr("hello"),
			expected: types.StringValue("hello"),
		},
		{
			name:     "string with spaces",
			input:    strPtr("hello world"),
			expected: types.StringValue("hello world"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stringPointerValueOrNull(tt.input)
			if !got.Equal(tt.expected) {
				t.Errorf("stringPointerValueOrNull(%v) = %v, want %v", *tt.input, got, tt.expected)
			}
		})
	}
}

func TestStringPointerValueOrNull_ReturnsNull(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *string
	}{
		{
			name:  "nil pointer",
			input: nil,
		},
		{
			name:  "empty string pointer",
			input: strPtr(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stringPointerValueOrNull(tt.input)
			expected := types.StringNull()
			if !got.Equal(expected) {
				t.Errorf("stringPointerValueOrNull(%v) = %v, want %v", tt.input, got, expected)
			}
		})
	}
}

// strPtr is a test helper that returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}
