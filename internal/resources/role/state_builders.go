// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *RoleResource) apiToState(_ context.Context, data *RoleResourceModel, api jamfprotect.Role) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	readLabels := rolePermissionListToLabels(api.Permissions.Read)
	if len(readLabels) == 0 && (data.ReadPermissions.IsNull() || data.ReadPermissions.IsUnknown()) {
		data.ReadPermissions = types.SetNull(types.StringType)
	} else {
		data.ReadPermissions = common.StringsToSet(readLabels)
	}

	writeLabels := rolePermissionListToLabels(api.Permissions.Write)
	if len(writeLabels) == 0 && (data.WritePermissions.IsNull() || data.WritePermissions.IsUnknown()) {
		data.WritePermissions = types.SetNull(types.StringType)
	} else {
		data.WritePermissions = common.StringsToSet(writeLabels)
	}
}

// roleAPIToDataSourceItem maps API role data to a data source item.
func roleAPIToDataSourceItem(api jamfprotect.Role) RoleDataSourceItemModel {
	readLabels := rolePermissionListToLabels(api.Permissions.Read)
	writeLabels := rolePermissionListToLabels(api.Permissions.Write)

	item := RoleDataSourceItemModel{
		ID:              types.StringValue(api.ID),
		Name:            types.StringValue(api.Name),
		ReadPermissions: common.StringsToSet(readLabels),
		Created:         types.StringValue(api.Created),
		Updated:         types.StringValue(api.Updated),
	}

	if len(writeLabels) == 0 {
		item.WritePermissions = types.SetNull(types.StringType)
	} else {
		item.WritePermissions = common.StringsToSet(writeLabels)
	}

	return item
}
