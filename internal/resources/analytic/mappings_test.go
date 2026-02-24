package analytic

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// TestMapSensorTypeUIToAPI_ValidMappings verifies every supported UI name maps to the correct API value.
func TestMapSensorTypeUIToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "file system event",
			input:    "File System Event",
			expected: "GPFSEvent",
		},
		{
			name:     "download event",
			input:    "Download Event",
			expected: "GPDownloadEvent",
		},
		{
			name:     "process event",
			input:    "Process Event",
			expected: "GPProcessEvent",
		},
		{
			name:     "screenshot event",
			input:    "Screenshot Event",
			expected: "GPScreenshotEvent",
		},
		{
			name:     "keylog register event",
			input:    "Keylog Register Event",
			expected: "GPKeylogRegisterEvent",
		},
		{
			name:     "synthetic click event",
			input:    "Synthetic Click Event",
			expected: "GPClickEvent",
		},
		{
			name:     "malware removal tool event",
			input:    "Malware Removal Tool Event",
			expected: "GPMRTEvent",
		},
		{
			name:     "usb event",
			input:    "USB Event",
			expected: "GPUSBEvent",
		},
		{
			name:     "gatekeeper event",
			input:    "Gatekeeper Event",
			expected: "GPGatekeeperEvent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			got := mapSensorTypeUIToAPI(tt.input, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestMapSensorTypeUIToAPI_UnknownValue verifies that an unrecognized UI name produces a diagnostic error and returns an empty string.
func TestMapSensorTypeUIToAPI_UnknownValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapSensorTypeUIToAPI("Unknown Sensor", &diags)

	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for unknown sensor type")
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// TestMapSensorTypeAPIToUI_ValidMappings verifies every supported API value maps to the correct UI name.
func TestMapSensorTypeAPIToUI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "GPFSEvent",
			input:    "GPFSEvent",
			expected: "File System Event",
		},
		{
			name:     "GPDownloadEvent",
			input:    "GPDownloadEvent",
			expected: "Download Event",
		},
		{
			name:     "GPProcessEvent",
			input:    "GPProcessEvent",
			expected: "Process Event",
		},
		{
			name:     "GPScreenshotEvent",
			input:    "GPScreenshotEvent",
			expected: "Screenshot Event",
		},
		{
			name:     "GPKeylogRegisterEvent",
			input:    "GPKeylogRegisterEvent",
			expected: "Keylog Register Event",
		},
		{
			name:     "GPClickEvent",
			input:    "GPClickEvent",
			expected: "Synthetic Click Event",
		},
		{
			name:     "GPMRTEvent",
			input:    "GPMRTEvent",
			expected: "Malware Removal Tool Event",
		},
		{
			name:     "GPUSBEvent",
			input:    "GPUSBEvent",
			expected: "USB Event",
		},
		{
			name:     "GPGatekeeperEvent",
			input:    "GPGatekeeperEvent",
			expected: "Gatekeeper Event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			got := mapSensorTypeAPIToUI(tt.input, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestMapSensorTypeAPIToUI_UnknownValue verifies that an unrecognized API value produces a diagnostic error and returns the original value.
func TestMapSensorTypeAPIToUI_UnknownValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := mapSensorTypeAPIToUI("GPUnknownEvent", &diags)

	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for unknown sensor type")
	}
	if got != "GPUnknownEvent" {
		t.Errorf("expected original value %q, got %q", "GPUnknownEvent", got)
	}
}

// TestNormalizeFilterValue_ReplacesDoubleBackslashes verifies that double backslashes are replaced with single backslashes.
func TestNormalizeFilterValue_ReplacesDoubleBackslashes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single double backslash",
			input:    "path\\\\to\\\\file",
			expected: "path\\to\\file",
		},
		{
			name:     "no backslashes",
			input:    "plain text",
			expected: "plain text",
		},
		{
			name:     "single backslash unchanged",
			input:    "path\\to\\file",
			expected: "path\\to\\file",
		},
		{
			name:     "multiple consecutive double backslashes",
			input:    "a\\\\\\\\b",
			expected: "a\\\\b",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeFilterValue(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
