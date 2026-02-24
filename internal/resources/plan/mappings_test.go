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
