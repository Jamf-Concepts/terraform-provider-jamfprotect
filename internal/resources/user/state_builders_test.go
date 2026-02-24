// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"testing"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// TestUserRoleIDs_PopulatedSlice verifies that role IDs are correctly extracted from a populated slice.
func TestUserRoleIDs_PopulatedSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		roles    []jamfprotect.UserRole
		expected []string
	}{
		{
			name: "multiple roles",
			roles: []jamfprotect.UserRole{
				{ID: "role-1", Name: "Admin"},
				{ID: "role-2", Name: "Auditor"},
				{ID: "role-3", Name: "Viewer"},
			},
			expected: []string{"role-1", "role-2", "role-3"},
		},
		{
			name: "single role",
			roles: []jamfprotect.UserRole{
				{ID: "role-only", Name: "Single"},
			},
			expected: []string{"role-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := common.MapSlice(tt.roles, func(r jamfprotect.UserRole) string { return r.ID })
			if len(got) != len(tt.expected) {
				t.Fatalf("MapSlice() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, id := range got {
				if id != tt.expected[i] {
					t.Errorf("MapSlice()[%d] = %q, want %q", i, id, tt.expected[i])
				}
			}
		})
	}
}

// TestUserRoleIDs_EmptySlice verifies that an empty slice returns nil.
func TestUserRoleIDs_EmptySlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice([]jamfprotect.UserRole{}, func(r jamfprotect.UserRole) string { return r.ID })
	if got != nil {
		t.Errorf("MapSlice(empty) = %v, want nil", got)
	}
}

// TestUserRoleIDs_NilSlice verifies that a nil slice returns nil.
func TestUserRoleIDs_NilSlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice([]jamfprotect.UserRole(nil), func(r jamfprotect.UserRole) string { return r.ID })
	if got != nil {
		t.Errorf("MapSlice(nil) = %v, want nil", got)
	}
}

// TestUserGroupIDs_PopulatedSlice verifies that group IDs are correctly extracted from a populated slice.
func TestUserGroupIDs_PopulatedSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		groups   []jamfprotect.UserGroup
		expected []string
	}{
		{
			name: "multiple groups",
			groups: []jamfprotect.UserGroup{
				{ID: "group-1", Name: "Engineering"},
				{ID: "group-2", Name: "Security"},
				{ID: "group-3", Name: "Operations"},
			},
			expected: []string{"group-1", "group-2", "group-3"},
		},
		{
			name: "single group",
			groups: []jamfprotect.UserGroup{
				{ID: "group-only", Name: "Single"},
			},
			expected: []string{"group-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := common.MapSlice(tt.groups, func(g jamfprotect.UserGroup) string { return g.ID })
			if len(got) != len(tt.expected) {
				t.Fatalf("MapSlice() returned %d elements, want %d", len(got), len(tt.expected))
			}
			for i, id := range got {
				if id != tt.expected[i] {
					t.Errorf("MapSlice()[%d] = %q, want %q", i, id, tt.expected[i])
				}
			}
		})
	}
}

// TestUserGroupIDs_EmptySlice verifies that an empty slice returns nil.
func TestUserGroupIDs_EmptySlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice([]jamfprotect.UserGroup{}, func(g jamfprotect.UserGroup) string { return g.ID })
	if got != nil {
		t.Errorf("MapSlice(empty) = %v, want nil", got)
	}
}

// TestUserGroupIDs_NilSlice verifies that a nil slice returns nil.
func TestUserGroupIDs_NilSlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice([]jamfprotect.UserGroup(nil), func(g jamfprotect.UserGroup) string { return g.ID })
	if got != nil {
		t.Errorf("MapSlice(nil) = %v, want nil", got)
	}
}
