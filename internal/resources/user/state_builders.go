// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *UserResource) apiToState(_ context.Context, data *UserResourceModel, api jamfprotect.User) {
	data.ID = types.StringValue(api.ID)
	data.Email = types.StringValue(api.Email)
	data.SendEmailNotifications = types.BoolValue(api.ReceiveEmailAlert)
	data.EmailSeverity = types.StringValue(api.EmailAlertMinSeverity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	roleIDs := userRoleIDs(api.AssignedRoles)
	if len(roleIDs) == 0 && (data.RoleIDs.IsNull() || data.RoleIDs.IsUnknown()) {
		data.RoleIDs = types.SetNull(types.StringType)
	} else {
		data.RoleIDs = common.StringsToSet(roleIDs)
	}

	groupIDs := userGroupIDs(api.AssignedGroups)
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

func userRoleIDs(roles []jamfprotect.UserRole) []string {
	if len(roles) == 0 {
		return nil
	}
	ids := make([]string, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, role.ID)
	}
	return ids
}

func userGroupIDs(groups []jamfprotect.UserGroup) []string {
	if len(groups) == 0 {
		return nil
	}
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	return ids
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
		RoleIDs:                common.SortedStringsToList(userRoleIDs(api.AssignedRoles)),
		GroupIDs:               common.SortedStringsToList(userGroupIDs(api.AssignedGroups)),
	}

	if api.Connection != nil {
		item.IdentityProviderID = types.StringValue(api.Connection.ID)
	} else {
		item.IdentityProviderID = types.StringNull()
	}

	return item
}
