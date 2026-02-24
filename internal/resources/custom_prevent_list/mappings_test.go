// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func TestMapPreventTypeUIToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Team ID",
			input:    "Team ID",
			expected: "TEAMID",
		},
		{
			name:     "File Hash",
			input:    "File Hash",
			expected: "FILEHASH",
		},
		{
			name:     "Code Directory Hash",
			input:    "Code Directory Hash",
			expected: "CDHASH",
		},
		{
			name:     "Signing ID",
			input:    "Signing ID",
			expected: "SIGNINGID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := mapPreventTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if got != tt.expected {
				t.Errorf("mapPreventTypeUIToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapPreventTypeUIToAPI_APIValuePassthrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "TEAMID", input: "TEAMID"},
		{name: "FILEHASH", input: "FILEHASH"},
		{name: "CDHASH", input: "CDHASH"},
		{name: "SIGNINGID", input: "SIGNINGID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := mapPreventTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if got != tt.input {
				t.Errorf("mapPreventTypeUIToAPI(%q) = %q, want %q", tt.input, got, tt.input)
			}
		})
	}
}

func TestMapPreventTypeUIToAPI_EmptyString(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapPreventTypeUIToAPI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}
	if got != "" {
		t.Errorf("mapPreventTypeUIToAPI(\"\") = %q, want \"\"", got)
	}
}

func TestMapPreventTypeUIToAPI_UnknownValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapPreventTypeUIToAPI("InvalidType", &diags)
	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for unknown value")
	}
	if got != "" {
		t.Errorf("mapPreventTypeUIToAPI(\"InvalidType\") = %q, want \"\"", got)
	}
}

func TestMapPreventTypeAPIToUI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "TEAMID",
			input:    "TEAMID",
			expected: "Team ID",
		},
		{
			name:     "FILEHASH",
			input:    "FILEHASH",
			expected: "File Hash",
		},
		{
			name:     "CDHASH",
			input:    "CDHASH",
			expected: "Code Directory Hash",
		},
		{
			name:     "SIGNINGID",
			input:    "SIGNINGID",
			expected: "Signing ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := mapPreventTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if got != tt.expected {
				t.Errorf("mapPreventTypeAPIToUI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapPreventTypeAPIToUI_UIValuePassthrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "Team ID", input: "Team ID"},
		{name: "File Hash", input: "File Hash"},
		{name: "Code Directory Hash", input: "Code Directory Hash"},
		{name: "Signing ID", input: "Signing ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := mapPreventTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if got != tt.input {
				t.Errorf("mapPreventTypeAPIToUI(%q) = %q, want %q", tt.input, got, tt.input)
			}
		})
	}
}

func TestMapPreventTypeAPIToUI_EmptyString(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapPreventTypeAPIToUI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}
	if got != "" {
		t.Errorf("mapPreventTypeAPIToUI(\"\") = %q, want \"\"", got)
	}
}

func TestMapPreventTypeAPIToUI_UnknownValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapPreventTypeAPIToUI("UNKNOWN", &diags)
	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for unknown value")
	}
	if got != "UNKNOWN" {
		t.Errorf("mapPreventTypeAPIToUI(\"UNKNOWN\") = %q, want \"UNKNOWN\"", got)
	}
}
