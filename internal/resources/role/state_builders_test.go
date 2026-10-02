// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"context"
	"testing"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestAPIToState_LoneException verifies that a role holding Exception without ExceptionSet keeps it in state.
func TestAPIToState_LoneException(t *testing.T) {
	t.Parallel()

	data := RoleResourceModel{
		ReadPermissions:  types.SetNull(types.StringType),
		WritePermissions: types.SetNull(types.StringType),
	}
	r := RoleResource{}
	r.apiToState(context.Background(), &data, jamfprotect.Role{
		ID:          "1",
		Name:        "test",
		Permissions: &jamfprotect.RolePermissions{Read: []string{"Exception"}, Write: []string{"Exception"}},
	})

	want := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Exception")})
	if !data.ReadPermissions.Equal(want) {
		t.Errorf("read_permissions = %v, want %v", data.ReadPermissions, want)
	}
	if !data.WritePermissions.Equal(want) {
		t.Errorf("write_permissions = %v, want %v", data.WritePermissions, want)
	}
}

// TestRoleAPIToDataSourceItem_LoneException verifies that the data source reports Exception without ExceptionSet.
func TestRoleAPIToDataSourceItem_LoneException(t *testing.T) {
	t.Parallel()

	item := roleAPIToDataSourceItem(jamfprotect.Role{
		ID:          "1",
		Name:        "test",
		Permissions: &jamfprotect.RolePermissions{Read: []string{"Exception"}, Write: []string{"Exception"}},
	})

	want := types.ListValueMust(types.StringType, []attr.Value{types.StringValue("Exception")})
	if !item.ReadPermissions.Equal(want) {
		t.Errorf("read_permissions = %v, want %v", item.ReadPermissions, want)
	}
	if !item.WritePermissions.Equal(want) {
		t.Errorf("write_permissions = %v, want %v", item.WritePermissions, want)
	}
}
