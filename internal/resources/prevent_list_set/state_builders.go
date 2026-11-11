// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// applyState maps the API response into the Terraform state model.
func (r *PreventListSetResource) applyState(_ context.Context, data *PreventListSetResourceModel, api jamfprotect.PreventListSet, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Description = types.StringValue(api.Description)

	listIDs := make([]string, 0, len(api.PreventLists))
	for _, l := range api.PreventLists {
		listIDs = append(listIDs, l.ID)
	}
	data.PreventLists = common.StringsToSet(listIDs)
}

// preventListSetAPIToDataSourceItem maps a Jamf Protect prevent list set to PreventListSetDataSourceItemModel.
func preventListSetAPIToDataSourceItem(api jamfprotect.PreventListSet, diags *diag.Diagnostics) PreventListSetDataSourceItemModel {
	item := PreventListSetDataSourceItemModel{
		UUID:    types.StringValue(api.UUID),
		Name:    types.StringValue(api.Name),
		Created: types.StringValue(api.Created),
		Updated: types.StringValue(api.Updated),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	listVals := make([]attr.Value, 0, len(api.PreventLists))
	for _, l := range api.PreventLists {
		listVals = append(listVals, types.ObjectValueMust(preventListSetListAttrTypes, map[string]attr.Value{
			"id":   types.StringValue(l.ID),
			"name": types.StringValue(l.Name),
		}))
	}
	listList, d := types.ListValue(types.ObjectType{AttrTypes: preventListSetListAttrTypes}, listVals)
	diags.Append(d...)
	item.PreventLists = listList

	planVals := make([]attr.Value, 0, len(api.Plans))
	for _, p := range api.Plans {
		planVals = append(planVals, types.ObjectValueMust(preventListSetPlanAttrTypes, map[string]attr.Value{
			"id":   types.StringValue(p.ID),
			"name": types.StringValue(p.Name),
		}))
	}
	planList, d := types.ListValue(types.ObjectType{AttrTypes: preventListSetPlanAttrTypes}, planVals)
	diags.Append(d...)
	item.Plans = planList

	return item
}
