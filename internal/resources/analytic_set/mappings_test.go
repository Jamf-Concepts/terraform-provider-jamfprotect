// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import "testing"

// TestIsSystemAnalyticSetName_KnownNames verifies that all known system analytic set names return true.
func TestIsSystemAnalyticSetName_KnownNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "advanced threat controls",
			input: "Advanced Threat Controls",
		},
		{
			name:  "tamper prevention",
			input: "Tamper Prevention",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !isSystemAnalyticSetName(tt.input) {
				t.Errorf("expected %q to be a system analytic set name", tt.input)
			}
		})
	}
}

// TestIsSystemAnalyticSetName_CustomNames verifies that non-system names return false.
func TestIsSystemAnalyticSetName_CustomNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "custom name",
			input: "My Custom Analytic Set",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "lowercase system name",
			input: "advanced threat controls",
		},
		{
			name:  "partial match",
			input: "Advanced Threat",
		},
		{
			name:  "trailing space",
			input: "Tamper Prevention ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if isSystemAnalyticSetName(tt.input) {
				t.Errorf("expected %q to not be a system analytic set name", tt.input)
			}
		})
	}
}
