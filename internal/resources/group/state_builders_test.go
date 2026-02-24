package group

import (
	"testing"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

func TestGroupRoleIDs_PopulatedSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		roles    []jamfprotect.GroupRole
		expected []string
	}{
		{
			name: "multiple roles",
			roles: []jamfprotect.GroupRole{
				{ID: "role-1", Name: "Admin"},
				{ID: "role-2", Name: "Auditor"},
				{ID: "role-3", Name: "Viewer"},
			},
			expected: []string{"role-1", "role-2", "role-3"},
		},
		{
			name: "single role",
			roles: []jamfprotect.GroupRole{
				{ID: "role-only", Name: "Single"},
			},
			expected: []string{"role-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := common.MapSlice(tt.roles, func(r jamfprotect.GroupRole) string { return r.ID })
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

func TestGroupRoleIDs_EmptySlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice([]jamfprotect.GroupRole{}, func(r jamfprotect.GroupRole) string { return r.ID })
	if got != nil {
		t.Errorf("MapSlice(empty) = %v, want nil", got)
	}
}

func TestGroupRoleIDs_NilSlice(t *testing.T) {
	t.Parallel()

	got := common.MapSlice(nil, func(r jamfprotect.GroupRole) string { return r.ID })
	if got != nil {
		t.Errorf("MapSlice(nil) = %v, want nil", got)
	}
}
