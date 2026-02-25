// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"testing"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// TestEndpointThreatPreventionToMode_ValidMappings verifies all valid UI values map to the correct API mode.
func TestEndpointThreatPreventionToMode_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		expectedMode string
		expectedOK   bool
	}{
		{"block_and_report", "Block and report", "blocking", true},
		{"report_only", "Report only", "reportOnly", true},
		{"disable", "Disable", "disabled", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mode, ok := endpointThreatPreventionToMode(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("endpointThreatPreventionToMode(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if mode != tt.expectedMode {
				t.Errorf("endpointThreatPreventionToMode(%q) = %q, want %q", tt.input, mode, tt.expectedMode)
			}
		})
	}
}

// TestEndpointThreatPreventionToMode_Unknown verifies an unknown value returns empty string and false.
func TestEndpointThreatPreventionToMode_Unknown(t *testing.T) {
	t.Parallel()

	mode, ok := endpointThreatPreventionToMode("invalid")
	if ok {
		t.Errorf("endpointThreatPreventionToMode(%q) ok = true, want false", "invalid")
	}
	if mode != "" {
		t.Errorf("endpointThreatPreventionToMode(%q) = %q, want %q", "invalid", mode, "")
	}
}

// TestModeToEndpointThreatPrevention_ValidMappings verifies all valid API modes map to the correct UI value.
func TestModeToEndpointThreatPrevention_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		expectedUI string
		expectedOK bool
	}{
		{"blocking", "blocking", "Block and report", true},
		{"report_only", "reportOnly", "Report only", true},
		{"monitoring", "monitoring", "Report only", true},
		{"disabled", "disabled", "Disable", true},
		{"off", "off", "Disable", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ui, ok := modeToEndpointThreatPrevention(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("modeToEndpointThreatPrevention(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if ui != tt.expectedUI {
				t.Errorf("modeToEndpointThreatPrevention(%q) = %q, want %q", tt.input, ui, tt.expectedUI)
			}
		})
	}
}

// TestModeToEndpointThreatPrevention_Unknown verifies an unknown mode returns empty string and false.
func TestModeToEndpointThreatPrevention_Unknown(t *testing.T) {
	t.Parallel()

	ui, ok := modeToEndpointThreatPrevention("invalid")
	if ok {
		t.Errorf("modeToEndpointThreatPrevention(%q) ok = true, want false", "invalid")
	}
	if ui != "" {
		t.Errorf("modeToEndpointThreatPrevention(%q) = %q, want %q", "invalid", ui, "")
	}
}

// TestEndpointThreatPrevention_RoundTrip verifies that canonical values survive a UI->API->UI round trip.
func TestEndpointThreatPrevention_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ui   string
	}{
		{"block_and_report", "Block and report"},
		{"report_only", "Report only"},
		{"disable", "Disable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mode, ok := endpointThreatPreventionToMode(tt.ui)
			if !ok {
				t.Fatalf("endpointThreatPreventionToMode(%q) returned false", tt.ui)
			}
			back, ok := modeToEndpointThreatPrevention(mode)
			if !ok {
				t.Fatalf("modeToEndpointThreatPrevention(%q) returned false", mode)
			}
			if back != tt.ui {
				t.Errorf("round trip failed: %q -> %q -> %q", tt.ui, mode, back)
			}
		})
	}
}

// TestAdvancedThreatControlsToType_ValidMappings verifies UI advanced threat controls map to analytic set types.
func TestAdvancedThreatControlsToType_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		expectedType string
		expectedOK   bool
	}{
		{"block_and_report", "Block and report", "Prevent", true},
		{"report_only", "Report only", "Report", true},
		{"disable", "Disable", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			typ, ok := advancedThreatControlsToType(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("advancedThreatControlsToType(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if typ != tt.expectedType {
				t.Errorf("advancedThreatControlsToType(%q) = %q, want %q", tt.input, typ, tt.expectedType)
			}
		})
	}
}

// TestAdvancedThreatControlsToType_Unknown verifies an unknown value returns empty string and false.
func TestAdvancedThreatControlsToType_Unknown(t *testing.T) {
	t.Parallel()

	typ, ok := advancedThreatControlsToType("invalid")
	if ok {
		t.Errorf("advancedThreatControlsToType(%q) ok = true, want false", "invalid")
	}
	if typ != "" {
		t.Errorf("advancedThreatControlsToType(%q) = %q, want %q", "invalid", typ, "")
	}
}

// TestTamperPreventionToType_ValidMappings verifies UI tamper prevention values map to analytic set types.
func TestTamperPreventionToType_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		expectedType string
		expectedOK   bool
	}{
		{"block_and_report", "Block and report", "Prevent", true},
		{"disable", "Disable", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			typ, ok := tamperPreventionToType(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("tamperPreventionToType(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if typ != tt.expectedType {
				t.Errorf("tamperPreventionToType(%q) = %q, want %q", tt.input, typ, tt.expectedType)
			}
		})
	}
}

// TestTamperPreventionToType_Unknown verifies an unknown value returns empty string and false.
func TestTamperPreventionToType_Unknown(t *testing.T) {
	t.Parallel()

	typ, ok := tamperPreventionToType("invalid")
	if ok {
		t.Errorf("tamperPreventionToType(%q) ok = true, want false", "invalid")
	}
	if typ != "" {
		t.Errorf("tamperPreventionToType(%q) = %q, want %q", "invalid", typ, "")
	}
}

// TestFilterManagedAnalyticSets_NoManagedUUIDs verifies that sets without managed UUIDs pass through.
func TestFilterManagedAnalyticSets_NoManagedUUIDs(t *testing.T) {
	t.Parallel()

	sets := []jamfprotect.PlanAnalyticSetInput{
		{Type: "Report", UUID: "uuid-1"},
		{Type: "Prevent", UUID: "uuid-2"},
	}
	managedUUIDs := map[string]string{
		advancedThreatControlsName: "managed-atc",
		tamperPreventionName:       "managed-tp",
	}

	var diags diag.Diagnostics
	result := filterManagedAnalyticSets(sets, managedUUIDs, &diags)

	if diags.HasError() {
		t.Errorf("unexpected diagnostics: %v", diags.Errors())
	}
	if len(result) != 2 {
		t.Fatalf("filterManagedAnalyticSets returned %d entries, want 2", len(result))
	}
	if result[0].UUID != "uuid-1" || result[1].UUID != "uuid-2" {
		t.Errorf("unexpected result UUIDs: %v", result)
	}
}

// TestFilterManagedAnalyticSets_WithManagedUUIDs verifies that managed UUIDs cause a diagnostic error.
func TestFilterManagedAnalyticSets_WithManagedUUIDs(t *testing.T) {
	t.Parallel()

	managedUUIDs := map[string]string{
		advancedThreatControlsName: "managed-atc",
		tamperPreventionName:       "managed-tp",
	}
	sets := []jamfprotect.PlanAnalyticSetInput{
		{Type: "Prevent", UUID: "managed-atc"},
		{Type: "Report", UUID: "uuid-1"},
	}

	var diags diag.Diagnostics
	result := filterManagedAnalyticSets(sets, managedUUIDs, &diags)

	if !diags.HasError() {
		t.Fatal("expected diagnostic error when managed UUIDs are included")
	}
	if result != nil {
		t.Errorf("expected nil result when managed UUIDs are included, got %v", result)
	}
}

// TestFilterManagedAnalyticSets_EmptyInput verifies that an empty slice is returned as-is.
func TestFilterManagedAnalyticSets_EmptyInput(t *testing.T) {
	t.Parallel()

	managedUUIDs := map[string]string{
		advancedThreatControlsName: "managed-atc",
		tamperPreventionName:       "managed-tp",
	}

	var diags diag.Diagnostics
	result := filterManagedAnalyticSets(nil, managedUUIDs, &diags)

	if diags.HasError() {
		t.Errorf("unexpected diagnostics: %v", diags.Errors())
	}
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}

// TestFilterManagedAnalyticSetEntries_RemovesManagedSets verifies managed sets are filtered out.
func TestFilterManagedAnalyticSetEntries_RemovesManagedSets(t *testing.T) {
	t.Parallel()

	sets := []jamfprotect.PlanAnalyticSet{
		{Type: "Prevent", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: "uuid-1", Name: advancedThreatControlsName}},
		{Type: "Report", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: "uuid-2", Name: "Custom Analytics"}},
		{Type: "Prevent", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: "uuid-3", Name: tamperPreventionName}},
	}

	result := filterManagedAnalyticSetEntries(sets)

	if len(result) != 1 {
		t.Fatalf("filterManagedAnalyticSetEntries returned %d entries, want 1", len(result))
	}
	if result[0].AnalyticSet.Name != "Custom Analytics" {
		t.Errorf("expected remaining entry to be %q, got %q", "Custom Analytics", result[0].AnalyticSet.Name)
	}
}

// TestFilterManagedAnalyticSetEntries_EmptyInput verifies an empty input returns nil.
func TestFilterManagedAnalyticSetEntries_EmptyInput(t *testing.T) {
	t.Parallel()

	result := filterManagedAnalyticSetEntries(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}

	result = filterManagedAnalyticSetEntries([]jamfprotect.PlanAnalyticSet{})
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

// TestFilterManagedAnalyticSetEntries_NoManaged verifies non-managed sets pass through.
func TestFilterManagedAnalyticSetEntries_NoManaged(t *testing.T) {
	t.Parallel()

	sets := []jamfprotect.PlanAnalyticSet{
		{Type: "Report", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: "uuid-1", Name: "Custom Set A"}},
		{Type: "Prevent", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: "uuid-2", Name: "Custom Set B"}},
	}

	result := filterManagedAnalyticSetEntries(sets)

	if len(result) != 2 {
		t.Fatalf("filterManagedAnalyticSetEntries returned %d entries, want 2", len(result))
	}
}

