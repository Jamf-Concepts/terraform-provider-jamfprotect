// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import "testing"

// TestEventTypeAttrName verifies the attribute name suffix is appended correctly.
func TestEventTypeAttrName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tfName   string
		expected string
	}{
		{"binary", "binary", "binary_included_data_attributes"},
		{"process_event", "process_event", "process_event_included_data_attributes"},
		{"file_system_event", "file_system_event", "file_system_event_included_data_attributes"},
		{"gatekeeper_event", "gatekeeper_event", "gatekeeper_event_included_data_attributes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eventTypeAttrName(tt.tfName)
			if got != tt.expected {
				t.Errorf("eventTypeAttrName(%q) = %q, want %q", tt.tfName, got, tt.expected)
			}
		})
	}
}
