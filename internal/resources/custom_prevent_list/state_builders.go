// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"context"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/attr"

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

	data.Description = types.StringValue(api.Description)
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
	item.Description = types.StringValue(api.Description)

	setVals := make([]attr.Value, 0, len(api.Sets))
	for _, s := range api.Sets {
		setVals = append(setVals, types.ObjectValueMust(preventListSetAttrTypes, map[string]attr.Value{
			"uuid": types.StringValue(s.UUID),
			"name": types.StringValue(s.Name),
		}))
	}
	setList, d := types.ListValue(types.ObjectType{AttrTypes: preventListSetAttrTypes}, setVals)
	diags.Append(d...)
	item.Sets = setList
	return item
}

// preventListSetAttrTypes defines the attribute types for the prevent list sets a list belongs to.
var preventListSetAttrTypes = map[string]attr.Type{
	"uuid": types.StringType,
	"name": types.StringType,
}
