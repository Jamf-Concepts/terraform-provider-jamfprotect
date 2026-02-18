// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// applyState maps the API response into the Terraform state model.
func (r *CustomPreventListResource) applyState(_ context.Context, data *CustomPreventListResourceModel, api jamfprotect.CustomPreventList, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.PreventType = types.StringValue(mapPreventTypeAPIToUI(api.Type, diags))
	data.EntryCount = types.Int64Value(api.Count)
	data.Created = types.StringValue(api.Created)
	data.ListData = common.StringsToList(api.List)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}
}

// customPreventListAPIToDataSourceItem maps a Jamf Protect prevent list to CustomPreventListDataSourceItemModel.
func customPreventListAPIToDataSourceItem(api jamfprotect.CustomPreventList, diags *diag.Diagnostics) CustomPreventListDataSourceItemModel {
	item := CustomPreventListDataSourceItemModel{
		ID:          types.StringValue(api.ID),
		Name:        types.StringValue(api.Name),
		PreventType: types.StringValue(mapPreventTypeAPIToUI(api.Type, diags)),
		EntryCount:  types.Int64Value(api.Count),
		ListData:    common.StringsToList(api.List),
		Created:     types.StringValue(api.Created),
	}
	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringValue("")
	}
	return item
}
