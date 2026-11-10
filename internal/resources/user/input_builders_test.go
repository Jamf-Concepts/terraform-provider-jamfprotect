// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildUserInput_ListFields verifies null or unknown role and group ids are omitted and known sets are sent.
func TestBuildUserInput_ListFields(t *testing.T) {
	t.Parallel()

	empty := types.SetValueMust(types.StringType, []attr.Value{})
	one := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("1")})
	null := types.SetNull(types.StringType)

	tests := []struct {
		name                string
		roles, groups       types.Set
		rolesNil, groupsNil bool
		rolesLen, groupsLen int
	}{
		{name: "both null omitted", roles: null, groups: null, rolesNil: true, groupsNil: true},
		{name: "both unknown omitted", roles: types.SetUnknown(types.StringType), groups: types.SetUnknown(types.StringType), rolesNil: true, groupsNil: true},
		{name: "roles empty clears, groups null omitted", roles: empty, groups: null, groupsNil: true},
		{name: "roles null omitted, groups populated", roles: null, groups: one, rolesNil: true, groupsLen: 1},
		{name: "both populated", roles: one, groups: one, rolesLen: 1, groupsLen: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := buildUserInput(context.Background(), UserResourceModel{Email: types.StringValue("a@example.com"), RoleIDs: tt.roles, GroupIDs: tt.groups}, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if (got.RoleIDs == nil) != tt.rolesNil || len(got.RoleIDs) != tt.rolesLen {
				t.Fatalf("RoleIDs = %#v, want nil=%v len=%d", got.RoleIDs, tt.rolesNil, tt.rolesLen)
			}
			if (got.GroupIDs == nil) != tt.groupsNil || len(got.GroupIDs) != tt.groupsLen {
				t.Fatalf("GroupIDs = %#v, want nil=%v len=%d", got.GroupIDs, tt.groupsNil, tt.groupsLen)
			}
		})
	}
}
