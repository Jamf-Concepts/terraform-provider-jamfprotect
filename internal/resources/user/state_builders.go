// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// apiToState maps the API response into the Terraform state model.
func (r *UserResource) apiToState(_ context.Context, data *UserResourceModel, api jamfprotect.User) {
	data.ID = types.StringValue(api.ID)
	data.Email = types.StringValue(api.Email)
	data.SendEmailNotifications = types.BoolValue(api.ReceiveEmailAlert)
	data.EmailSeverity = types.StringValue(api.EmailAlertMinSeverity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	roleIDs := common.MapSlice(api.AssignedRoles, func(r jamfprotect.UserRole) string { return r.ID })
	if len(roleIDs) == 0 && (data.RoleIDs.IsNull() || data.RoleIDs.IsUnknown()) {
		data.RoleIDs = types.SetNull(types.StringType)
	} else {
		data.RoleIDs = common.StringsToSet(roleIDs)
	}

	groupIDs := common.MapSlice(api.AssignedGroups, func(g jamfprotect.UserGroup) string { return g.ID })
	if len(groupIDs) == 0 && (data.GroupIDs.IsNull() || data.GroupIDs.IsUnknown()) {
		data.GroupIDs = types.SetNull(types.StringType)
	} else {
		data.GroupIDs = common.StringsToSet(groupIDs)
	}

	if api.Connection != nil {
		data.IdentityProviderID = types.StringValue(api.Connection.ID)
	} else {
		data.IdentityProviderID = types.StringNull()
	}
}

// userAPIToDataSourceItem maps API user data to a data source item.
func userAPIToDataSourceItem(api jamfprotect.User) UserDataSourceItemModel {
	item := UserDataSourceItemModel{
		ID:                     types.StringValue(api.ID),
		Email:                  types.StringValue(api.Email),
		SendEmailNotifications: types.BoolValue(api.ReceiveEmailAlert),
		EmailSeverity:          types.StringValue(api.EmailAlertMinSeverity),
		Created:                types.StringValue(api.Created),
		Updated:                types.StringValue(api.Updated),
		RoleIDs:                common.SortedStringsToList(common.MapSlice(api.AssignedRoles, func(r jamfprotect.UserRole) string { return r.ID })),
		GroupIDs:               common.SortedStringsToList(common.MapSlice(api.AssignedGroups, func(g jamfprotect.UserGroup) string { return g.ID })),
	}

	if api.Connection != nil {
		item.IdentityProviderID = types.StringValue(api.Connection.ID)
	} else {
		item.IdentityProviderID = types.StringNull()
	}

	return item
}
