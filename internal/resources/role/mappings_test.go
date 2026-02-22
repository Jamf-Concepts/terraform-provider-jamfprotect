// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// TestRolePermissionAPIValue_ValidLabels verifies that all known UI labels resolve to the correct API values.
func TestRolePermissionAPIValue_ValidLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		label    string
		expected string
	}{
		{"all lowercase", "all", "all"},
		{"All titlecase", "All", "all"},
		{"Account Groups & Mappings", "Account Groups & Mappings", "Group"},
		{"Account Identity Providers", "Account Identity Providers", "Connection"},
		{"Account Roles", "Account Roles", "Role"},
		{"Account Users", "Account Users", "User"},
		{"Actions", "Actions", "ActionConfigs"},
		{"Alerts", "Alerts", "Alert"},
		{"Analytic Sets", "Analytic Sets", "AnalyticSet"},
		{"Analytics", "Analytics", "Analytic"},
		{"API Clients", "API Clients", "ApiClient"},
		{"Change Management", "Change Management", "ConfigFreeze"},
		{"Compliance", "Compliance", "Insight"},
		{"Computers", "Computers", "Computer"},
		{"Data Forwarding", "Data Forwarding", "DataForward"},
		{"Data Retention", "Data Retention", "DataRetention"},
		{"Downloads", "Downloads", "Download"},
		{"Exception Sets", "Exception Sets", "ExceptionSet"},
		{"Plans", "Plans", "Plan"},
		{"Prevent Lists", "Prevent Lists", "PreventList"},
		{"Removable Storage Control Sets", "Removable Storage Control Sets", "USBControlSet"},
		{"Telemetry", "Telemetry", "Telemetry"},
		{"Unified Logging", "Unified Logging", "UnifiedLoggingFilter"},
		{"Account Information", "Account Information", "Organization"},
		{"Audit Logs", "Audit Logs", "AuditLog"},
		{"Endpoint Threat Prevention", "Endpoint Threat Prevention", "ThreatPreventionVersion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := rolePermissionAPIValue(tt.label)
			if !ok {
				t.Fatalf("rolePermissionAPIValue(%q) returned ok=false, want true", tt.label)
			}
			if got != tt.expected {
				t.Errorf("rolePermissionAPIValue(%q) = %q, want %q", tt.label, got, tt.expected)
			}
		})
	}
}

// TestRolePermissionAPIValue_ExceptionPassthrough verifies that "Exception" is accepted as a passthrough value.
func TestRolePermissionAPIValue_ExceptionPassthrough(t *testing.T) {
	t.Parallel()

	got, ok := rolePermissionAPIValue("Exception")
	if !ok {
		t.Fatal("rolePermissionAPIValue(\"Exception\") returned ok=false, want true")
	}
	if got != "Exception" {
		t.Errorf("rolePermissionAPIValue(\"Exception\") = %q, want %q", got, "Exception")
	}
}

// TestRolePermissionAPIValue_RawAPIValue verifies that a known API value passes through when not in the label map.
func TestRolePermissionAPIValue_RawAPIValue(t *testing.T) {
	t.Parallel()

	got, ok := rolePermissionAPIValue("Computer")
	if !ok {
		t.Fatal("rolePermissionAPIValue(\"Computer\") returned ok=false, want true")
	}
	if got != "Computer" {
		t.Errorf("rolePermissionAPIValue(\"Computer\") = %q, want %q", got, "Computer")
	}
}

// TestRolePermissionAPIValue_Unknown verifies that an unrecognised value returns false.
func TestRolePermissionAPIValue_Unknown(t *testing.T) {
	t.Parallel()

	_, ok := rolePermissionAPIValue("CompletelyUnknown")
	if ok {
		t.Error("rolePermissionAPIValue(\"CompletelyUnknown\") returned ok=true, want false")
	}
}

// TestRolePermissionLabel_ValidAPIValues verifies that all known API values resolve to the correct UI labels.
func TestRolePermissionLabel_ValidAPIValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apiValue string
		expected string
	}{
		{"all", "all", "all"},
		{"Group", "Group", "Account Groups & Mappings"},
		{"Connection", "Connection", "Account Identity Providers"},
		{"Role", "Role", "Account Roles"},
		{"User", "User", "Account Users"},
		{"ActionConfigs", "ActionConfigs", "Actions"},
		{"Alert", "Alert", "Alerts"},
		{"AnalyticSet", "AnalyticSet", "Analytic Sets"},
		{"Analytic", "Analytic", "Analytics"},
		{"ApiClient", "ApiClient", "API Clients"},
		{"ConfigFreeze", "ConfigFreeze", "Change Management"},
		{"Insight", "Insight", "Compliance"},
		{"Computer", "Computer", "Computers"},
		{"DataForward", "DataForward", "Data Forwarding"},
		{"DataRetention", "DataRetention", "Data Retention"},
		{"Download", "Download", "Downloads"},
		{"ExceptionSet", "ExceptionSet", "Exception Sets"},
		{"Plan", "Plan", "Plans"},
		{"PreventList", "PreventList", "Prevent Lists"},
		{"USBControlSet", "USBControlSet", "Removable Storage Control Sets"},
		{"Telemetry", "Telemetry", "Telemetry"},
		{"UnifiedLoggingFilter", "UnifiedLoggingFilter", "Unified Logging"},
		{"Organization", "Organization", "Account Information"},
		{"AuditLog", "AuditLog", "Audit Logs"},
		{"ThreatPreventionVersion", "ThreatPreventionVersion", "Endpoint Threat Prevention"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rolePermissionLabel(tt.apiValue)
			if got != tt.expected {
				t.Errorf("rolePermissionLabel(%q) = %q, want %q", tt.apiValue, got, tt.expected)
			}
		})
	}
}

// TestRolePermissionLabel_Unknown verifies that an unrecognised API value is returned as-is.
func TestRolePermissionLabel_Unknown(t *testing.T) {
	t.Parallel()

	got := rolePermissionLabel("UnknownValue")
	if got != "UnknownValue" {
		t.Errorf("rolePermissionLabel(\"UnknownValue\") = %q, want %q", got, "UnknownValue")
	}
}

// TestRolePermissionListToAPI_ValidLabels verifies that valid labels are converted to sorted API values.
func TestRolePermissionListToAPI_ValidLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		labels   []string
		expected []string
	}{
		{
			name:     "single label",
			labels:   []string{"Computers"},
			expected: []string{"Computer"},
		},
		{
			name:     "multiple labels sorted output",
			labels:   []string{"Unified Logging", "Actions", "Computers"},
			expected: []string{"ActionConfigs", "Computer", "UnifiedLoggingFilter"},
		},
		{
			name:     "all permission",
			labels:   []string{"all"},
			expected: []string{"all"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := rolePermissionListToAPI(tt.labels, &diags, "test_field")
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if len(got) != len(tt.expected) {
				t.Fatalf("rolePermissionListToAPI() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("rolePermissionListToAPI()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestRolePermissionListToAPI_InvalidLabel verifies that an invalid label adds a diagnostic error.
func TestRolePermissionListToAPI_InvalidLabel(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := rolePermissionListToAPI([]string{"Computers", "NotAPermission"}, &diags, "write_permissions")
	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for invalid label, got none")
	}

	// The valid label should still be present in the output.
	if len(got) != 1 || got[0] != "Computer" {
		t.Errorf("rolePermissionListToAPI() = %v, want [Computer]", got)
	}
}

// TestRolePermissionListToAPI_DuplicateLabels verifies that duplicate labels are deduplicated.
func TestRolePermissionListToAPI_DuplicateLabels(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := rolePermissionListToAPI([]string{"Computers", "Computers", "Alerts"}, &diags, "test_field")
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	expected := []string{"Alert", "Computer"}
	if len(got) != len(expected) {
		t.Fatalf("rolePermissionListToAPI() returned %d elements, want %d", len(got), len(expected))
	}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("rolePermissionListToAPI()[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

// TestRolePermissionListToAPI_EmptyInput verifies that an empty slice returns nil.
func TestRolePermissionListToAPI_EmptyInput(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := rolePermissionListToAPI([]string{}, &diags, "test_field")
	if got != nil {
		t.Errorf("rolePermissionListToAPI(empty) = %v, want nil", got)
	}
}

// TestRolePermissionListToAPI_NilInput verifies that a nil slice returns nil.
func TestRolePermissionListToAPI_NilInput(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := rolePermissionListToAPI(nil, &diags, "test_field")
	if got != nil {
		t.Errorf("rolePermissionListToAPI(nil) = %v, want nil", got)
	}
}

// TestRolePermissionListToLabels_ValidAPIValues verifies that API values are converted to sorted UI labels.
func TestRolePermissionListToLabels_ValidAPIValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		values   []string
		expected []string
	}{
		{
			name:     "single value",
			values:   []string{"Computer"},
			expected: []string{"Computers"},
		},
		{
			name:     "multiple values sorted output",
			values:   []string{"UnifiedLoggingFilter", "ActionConfigs", "Computer"},
			expected: []string{"Actions", "Computers", "Unified Logging"},
		},
		{
			name:     "all permission",
			values:   []string{"all"},
			expected: []string{"all"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rolePermissionListToLabels(tt.values)
			if len(got) != len(tt.expected) {
				t.Fatalf("rolePermissionListToLabels() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("rolePermissionListToLabels()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestRolePermissionListToLabels_ExceptionFiltered verifies that "Exception" entries are skipped in output.
func TestRolePermissionListToLabels_ExceptionFiltered(t *testing.T) {
	t.Parallel()

	got := rolePermissionListToLabels([]string{"ExceptionSet", "Exception", "Computer"})
	expected := []string{"Computers", "Exception Sets"}
	if len(got) != len(expected) {
		t.Fatalf("rolePermissionListToLabels() returned %d elements, want %d", len(got), len(expected))
	}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("rolePermissionListToLabels()[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

// TestRolePermissionListToLabels_DuplicateValues verifies that duplicate API values are deduplicated.
func TestRolePermissionListToLabels_DuplicateValues(t *testing.T) {
	t.Parallel()

	got := rolePermissionListToLabels([]string{"Computer", "Computer", "Alert"})
	expected := []string{"Alerts", "Computers"}
	if len(got) != len(expected) {
		t.Fatalf("rolePermissionListToLabels() returned %d elements, want %d", len(got), len(expected))
	}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("rolePermissionListToLabels()[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

// TestRolePermissionListToLabels_EmptyInput verifies that an empty slice returns nil.
func TestRolePermissionListToLabels_EmptyInput(t *testing.T) {
	t.Parallel()

	got := rolePermissionListToLabels([]string{})
	if got != nil {
		t.Errorf("rolePermissionListToLabels(empty) = %v, want nil", got)
	}
}

// TestRolePermissionListToLabels_NilInput verifies that a nil slice returns nil.
func TestRolePermissionListToLabels_NilInput(t *testing.T) {
	t.Parallel()

	got := rolePermissionListToLabels(nil)
	if got != nil {
		t.Errorf("rolePermissionListToLabels(nil) = %v, want nil", got)
	}
}

// TestRolePermissionHasAll_Present verifies that a slice containing "all" returns true.
func TestRolePermissionHasAll_Present(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{"only all", []string{"all"}},
		{"all with others", []string{"Computer", "all", "Alert"}},
		{"all at end", []string{"Computer", "Alert", "all"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !rolePermissionHasAll(tt.values) {
				t.Errorf("rolePermissionHasAll(%v) = false, want true", tt.values)
			}
		})
	}
}

// TestRolePermissionHasAll_Absent verifies that a slice without "all" returns false.
func TestRolePermissionHasAll_Absent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{"no all", []string{"Computer", "Alert"}},
		{"empty slice", []string{}},
		{"nil slice", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if rolePermissionHasAll(tt.values) {
				t.Errorf("rolePermissionHasAll(%v) = true, want false", tt.values)
			}
		})
	}
}
