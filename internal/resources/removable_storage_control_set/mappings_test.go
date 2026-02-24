package removable_storage_control_set

import "testing"

// TestPermissionToAPI_ValidMappings verifies UI permission options map to the correct API values.
func TestPermissionToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"prevent", "Prevent", "Prevented"},
		{"read_and_write", "Read and Write", "ReadWrite"},
		{"read_only", "Read Only", "ReadOnly"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := permissionToAPI(tt.input)
			if got != tt.expected {
				t.Errorf("permissionToAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestPermissionToAPI_Unknown verifies an unknown value is returned unchanged.
func TestPermissionToAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := permissionToAPI("unknown-permission")
	if got != "unknown-permission" {
		t.Errorf("permissionToAPI(%q) = %q, want %q", "unknown-permission", got, "unknown-permission")
	}
}

// TestPermissionFromAPI_ValidMappings verifies API permission values map back to UI options.
func TestPermissionFromAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"prevented", "Prevented", "Prevent"},
		{"read_write", "ReadWrite", "Read and Write"},
		{"read_only", "ReadOnly", "Read Only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := permissionFromAPI(tt.input)
			if got != tt.expected {
				t.Errorf("permissionFromAPI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestPermissionFromAPI_Unknown verifies an unknown API value is returned unchanged.
func TestPermissionFromAPI_Unknown(t *testing.T) {
	t.Parallel()

	got := permissionFromAPI("UnknownValue")
	if got != "UnknownValue" {
		t.Errorf("permissionFromAPI(%q) = %q, want %q", "UnknownValue", got, "UnknownValue")
	}
}

// TestPermission_RoundTrip verifies that every valid mapping survives a UI->API->UI round trip.
func TestPermission_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, ui := range permissionUIOptions {
		t.Run(ui, func(t *testing.T) {
			t.Parallel()
			api := permissionToAPI(ui)
			back := permissionFromAPI(api)
			if back != ui {
				t.Errorf("round trip failed: %q -> %q -> %q", ui, api, back)
			}
		})
	}
}

// TestNormalizeRemovableStorageRuleType_ValidTypes verifies known rule type suffixes are stripped.
func TestNormalizeRemovableStorageRuleType_ValidTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"vendor_rule", "VendorRule", "Vendor"},
		{"serial_rule", "SerialRule", "Serial"},
		{"product_rule", "ProductRule", "Product"},
		{"encryption_rule", "EncryptionRule", "Encryption"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeRemovableStorageRuleType(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeRemovableStorageRuleType(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestNormalizeRemovableStorageRuleType_Unknown verifies an unrecognized type is returned unchanged.
func TestNormalizeRemovableStorageRuleType_Unknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty_string", "", ""},
		{"already_normalized", "Vendor", "Vendor"},
		{"unknown_type", "CustomRule", "CustomRule"},
		{"lowercase", "vendorrule", "vendorrule"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeRemovableStorageRuleType(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeRemovableStorageRuleType(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
