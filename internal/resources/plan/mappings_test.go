// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import "testing"

// TestLogLevelToAPI verifies UI log level labels map to the correct API enum values.
func TestLogLevelToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"error", "Error", "ERROR"},
		{"warning", "Warning", "WARNING"},
		{"info", "Info", "INFO"},
		{"debug", "Debug", "DEBUG"},
		{"verbose", "Verbose", "VERBOSE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logLevelToAPI(tt.input)
			if got != tt.expected {
				t.Errorf("logLevelToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLogLevelToAPI_Unknown verifies that an unknown value is returned unchanged.
func TestLogLevelToAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := logLevelToAPI("unknown-value")
	if got != "unknown-value" {
		t.Errorf("logLevelToAPI(%q) = %q, want %q", "unknown-value", got, "unknown-value")
	}
}

// TestLogLevelFromAPI_ValidMappings verifies API enum values map back to UI labels.
func TestLogLevelFromAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"error", "ERROR", "Error"},
		{"warning", "WARNING", "Warning"},
		{"info", "INFO", "Info"},
		{"debug", "DEBUG", "Debug"},
		{"verbose", "VERBOSE", "Verbose"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logLevelFromAPI(tt.input)
			if got != tt.expected {
				t.Errorf("logLevelFromAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLogLevelFromAPI_Unknown verifies that an unknown API value is returned unchanged.
func TestLogLevelFromAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := logLevelFromAPI("UNKNOWN")
	if got != "UNKNOWN" {
		t.Errorf("logLevelFromAPI(%q) = %q, want %q", "UNKNOWN", got, "UNKNOWN")
	}
}

// TestLogLevel_RoundTrip verifies that every valid mapping survives a UI->API->UI round trip.
func TestLogLevel_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, ui := range logLevelUIOptions {
		t.Run(ui, func(t *testing.T) {
			t.Parallel()
			api := logLevelToAPI(ui)
			back := logLevelFromAPI(api)
			if back != ui {
				t.Errorf("round trip failed: %q -> %q -> %q", ui, api, back)
			}
		})
	}
}

// TestCommunicationsProtocolToAPI_ValidMappings verifies UI protocol labels map to API values.
func TestCommunicationsProtocolToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"mqtt", "MQTT:443", "mqtt"},
		{"wss_mqtt", "WebSocket/MQTT:443", "wss/mqtt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := communicationsProtocolToAPI(tt.input)
			if got != tt.expected {
				t.Errorf("communicationsProtocolToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestCommunicationsProtocolToAPI_Unknown verifies an unknown protocol passes through unchanged.
func TestCommunicationsProtocolToAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := communicationsProtocolToAPI("unknown-protocol")
	if got != "unknown-protocol" {
		t.Errorf("communicationsProtocolToAPI(%q) = %q, want %q", "unknown-protocol", got, "unknown-protocol")
	}
}

// TestCommunicationsProtocolFromAPI_ValidMappings verifies API protocol values map back to UI labels.
func TestCommunicationsProtocolFromAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"mqtt", "mqtt", "MQTT:443"},
		{"wss_mqtt", "wss/mqtt", "WebSocket/MQTT:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := communicationsProtocolFromAPI(tt.input)
			if got != tt.expected {
				t.Errorf("communicationsProtocolFromAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestCommunicationsProtocolFromAPI_Unknown verifies an unknown API value passes through unchanged.
func TestCommunicationsProtocolFromAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := communicationsProtocolFromAPI("unknown")
	if got != "unknown" {
		t.Errorf("communicationsProtocolFromAPI(%q) = %q, want %q", "unknown", got, "unknown")
	}
}

// TestCommunicationsProtocol_RoundTrip verifies that every valid mapping survives a UI->API->UI round trip.
func TestCommunicationsProtocol_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, ui := range communicationsProtocolUIOptions {
		t.Run(ui, func(t *testing.T) {
			t.Parallel()
			api := communicationsProtocolToAPI(ui)
			back := communicationsProtocolFromAPI(api)
			if back != ui {
				t.Errorf("round trip failed: %q -> %q -> %q", ui, api, back)
			}
		})
	}
}

// TestThreatPreventionStrategyToAPI_ValidMappings verifies UI strategy labels map to API enum values.
func TestThreatPreventionStrategyToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"legacy", "Legacy", "LEGACY"},
		{"managed", "Managed", "MANAGED"},
		{"custom", "Custom", "CUSTOM_ENGINES"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := threatPreventionStrategyToAPI(tt.input)
			if got != tt.expected {
				t.Errorf("threatPreventionStrategyToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestThreatPreventionStrategyToAPI_Unknown verifies an unknown value passes through unchanged.
func TestThreatPreventionStrategyToAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := threatPreventionStrategyToAPI("unknown")
	if got != "unknown" {
		t.Errorf("threatPreventionStrategyToAPI(%q) = %q, want %q", "unknown", got, "unknown")
	}
}

// TestThreatPreventionStrategyFromAPI_ValidMappings verifies API enum values map back to UI labels.
func TestThreatPreventionStrategyFromAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"legacy", "LEGACY", "Legacy"},
		{"managed", "MANAGED", "Managed"},
		{"custom_engines", "CUSTOM_ENGINES", "Custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := threatPreventionStrategyFromAPI(tt.input)
			if got != tt.expected {
				t.Errorf("threatPreventionStrategyFromAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestThreatPreventionStrategyFromAPI_Unknown verifies an unknown API value passes through unchanged.
func TestThreatPreventionStrategyFromAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := threatPreventionStrategyFromAPI("UNKNOWN_STRATEGY")
	if got != "UNKNOWN_STRATEGY" {
		t.Errorf("threatPreventionStrategyFromAPI(%q) = %q, want %q", "UNKNOWN_STRATEGY", got, "UNKNOWN_STRATEGY")
	}
}

// TestThreatPreventionStrategy_RoundTrip verifies every valid strategy survives a UI->API->UI round trip.
func TestThreatPreventionStrategy_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, ui := range threatPreventionStrategyUIOptions {
		t.Run(ui, func(t *testing.T) {
			t.Parallel()
			api := threatPreventionStrategyToAPI(ui)
			back := threatPreventionStrategyFromAPI(api)
			if back != ui {
				t.Errorf("round trip failed: %q -> %q -> %q", ui, api, back)
			}
		})
	}
}

// TestCustomEngineConfigModeToAPI_ValidMappings verifies UI mode labels map to API enum values.
func TestCustomEngineConfigModeToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		expected   string
		expectedOK bool
	}{
		{"block_and_report", "Block and report", "PREVENT", true},
		{"report_only", "Report only", "REPORT", true},
		{"disabled", "Disabled", "DISABLED", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := customEngineConfigModeToAPI(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("customEngineConfigModeToAPI(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if got != tt.expected {
				t.Errorf("customEngineConfigModeToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestCustomEngineConfigModeToAPI_Unknown verifies an unknown value returns empty string and false.
func TestCustomEngineConfigModeToAPI_Unknown(t *testing.T) {
	t.Parallel()

	got, ok := customEngineConfigModeToAPI("invalid")
	if ok {
		t.Errorf("customEngineConfigModeToAPI(%q) ok = true, want false", "invalid")
	}
	if got != "" {
		t.Errorf("customEngineConfigModeToAPI(%q) = %q, want %q", "invalid", got, "")
	}
}

// TestCustomEngineConfigModeFromAPI_ValidMappings verifies API enum values map back to UI labels.
func TestCustomEngineConfigModeFromAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		expected   string
		expectedOK bool
	}{
		{"prevent", "PREVENT", "Block and report", true},
		{"report", "REPORT", "Report only", true},
		{"disabled", "DISABLED", "Disabled", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := customEngineConfigModeFromAPI(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("customEngineConfigModeFromAPI(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if got != tt.expected {
				t.Errorf("customEngineConfigModeFromAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestCustomEngineConfigModeFromAPI_Unknown verifies an unknown API value returns empty string and false.
func TestCustomEngineConfigModeFromAPI_Unknown(t *testing.T) {
	t.Parallel()

	got, ok := customEngineConfigModeFromAPI("UNKNOWN_MODE")
	if ok {
		t.Errorf("customEngineConfigModeFromAPI(%q) ok = true, want false", "UNKNOWN_MODE")
	}
	if got != "" {
		t.Errorf("customEngineConfigModeFromAPI(%q) = %q, want %q", "UNKNOWN_MODE", got, "")
	}
}

// TestCustomEngineConfigMode_RoundTrip verifies every valid mode survives a UI->API->UI round trip.
func TestCustomEngineConfigMode_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, ui := range customEngineConfigModeUIOptions {
		t.Run(ui, func(t *testing.T) {
			t.Parallel()
			api, ok := customEngineConfigModeToAPI(ui)
			if !ok {
				t.Fatalf("customEngineConfigModeToAPI(%q) returned false", ui)
			}
			back, ok := customEngineConfigModeFromAPI(api)
			if !ok {
				t.Fatalf("customEngineConfigModeFromAPI(%q) returned false", api)
			}
			if back != ui {
				t.Errorf("round trip failed: %q -> %q -> %q", ui, api, back)
			}
		})
	}
}
