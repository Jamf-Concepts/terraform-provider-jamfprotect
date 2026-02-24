// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// TestApiClientRoleIDs_ExtractsIDs verifies that role IDs are correctly extracted from a slice of roles.
func TestApiClientRoleIDs_ExtractsIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		roles    []jamfprotect.ApiClientRole
		expected []string
	}{
		{
			name: "multiple roles",
			roles: []jamfprotect.ApiClientRole{
				{ID: "role-1", Name: "Admin"},
				{ID: "role-2", Name: "Reader"},
				{ID: "role-3", Name: "Writer"},
			},
			expected: []string{"role-1", "role-2", "role-3"},
		},
		{
			name: "single role",
			roles: []jamfprotect.ApiClientRole{
				{ID: "role-1", Name: "Admin"},
			},
			expected: []string{"role-1"},
		},
		{
			name:     "empty roles",
			roles:    []jamfprotect.ApiClientRole{},
			expected: nil,
		},
		{
			name:     "nil roles",
			roles:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := common.MapSlice(tt.roles, func(r jamfprotect.ApiClientRole) string { return r.ID })

			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d IDs, got %d", len(tt.expected), len(got))
			}
			for i, id := range got {
				if id != tt.expected[i] {
					t.Errorf("expected ID[%d] = %q, got %q", i, tt.expected[i], id)
				}
			}
		})
	}
}

// TestApiClientPasswordStateValue_MaskedWithKnownCurrent verifies that a masked API password preserves the current state value.
func TestApiClientPasswordStateValue_MaskedWithKnownCurrent(t *testing.T) {
	t.Parallel()

	current := types.StringValue("my-secret-password")

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "masked password",
			password: "*****",
		},
		{
			name:     "empty password",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := apiClientPasswordStateValue(current, tt.password)

			if got.IsNull() || got.IsUnknown() {
				t.Fatal("expected known value, got null or unknown")
			}
			if got.ValueString() != "my-secret-password" {
				t.Errorf("expected preserved value %q, got %q", "my-secret-password", got.ValueString())
			}
		})
	}
}

// TestApiClientPasswordStateValue_MaskedWithNullCurrent verifies that a masked API password returns null when the current state is null.
func TestApiClientPasswordStateValue_MaskedWithNullCurrent(t *testing.T) {
	t.Parallel()

	current := types.StringNull()

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "masked password",
			password: "*****",
		},
		{
			name:     "empty password",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := apiClientPasswordStateValue(current, tt.password)

			if !got.IsNull() {
				t.Errorf("expected null, got %q", got.ValueString())
			}
		})
	}
}

// TestApiClientPasswordStateValue_MaskedWithUnknownCurrent verifies that a masked API password returns null when the current state is unknown.
func TestApiClientPasswordStateValue_MaskedWithUnknownCurrent(t *testing.T) {
	t.Parallel()

	current := types.StringUnknown()
	got := apiClientPasswordStateValue(current, "*****")

	if !got.IsNull() {
		t.Errorf("expected null, got %q", got.ValueString())
	}
}

// TestApiClientPasswordStateValue_RealPassword verifies that a real (non-masked) password from the API is returned as-is.
func TestApiClientPasswordStateValue_RealPassword(t *testing.T) {
	t.Parallel()

	current := types.StringValue("old-password")
	got := apiClientPasswordStateValue(current, "new-real-password")

	if got.IsNull() || got.IsUnknown() {
		t.Fatal("expected known value, got null or unknown")
	}
	if got.ValueString() != "new-real-password" {
		t.Errorf("expected %q, got %q", "new-real-password", got.ValueString())
	}
}

// TestApiClientPasswordDataSourceValue_MaskedPasswords verifies that masked or empty passwords return null.
func TestApiClientPasswordDataSourceValue_MaskedPasswords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "masked password",
			password: "*****",
		},
		{
			name:     "empty password",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := apiClientPasswordDataSourceValue(tt.password)

			if !got.IsNull() {
				t.Errorf("expected null, got %q", got.ValueString())
			}
		})
	}
}

// TestApiClientPasswordDataSourceValue_RealPassword verifies that a real password is returned as a string value.
func TestApiClientPasswordDataSourceValue_RealPassword(t *testing.T) {
	t.Parallel()

	got := apiClientPasswordDataSourceValue("real-secret-password")

	if got.IsNull() || got.IsUnknown() {
		t.Fatal("expected known value, got null or unknown")
	}
	if got.ValueString() != "real-secret-password" {
		t.Errorf("expected %q, got %q", "real-secret-password", got.ValueString())
	}
}
