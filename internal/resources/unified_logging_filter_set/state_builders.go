// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// applyState maps the API response into the Terraform state model.
func (r *UnifiedLoggingFilterSetResource) applyState(_ context.Context, data *UnifiedLoggingFilterSetResourceModel, api jamfprotect.UnifiedLoggingFilterSet, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Description = types.StringValue(api.Description)

	filterUUIDs := make([]string, 0, len(api.Filters))
	for _, f := range api.Filters {
		filterUUIDs = append(filterUUIDs, f.UUID)
	}
	data.Filters = common.StringsToSet(filterUUIDs)
}

// filterSetAPIToDataSourceItem maps a Jamf Protect filter set to UnifiedLoggingFilterSetDataSourceItemModel.
func filterSetAPIToDataSourceItem(api jamfprotect.UnifiedLoggingFilterSet, diags *diag.Diagnostics) UnifiedLoggingFilterSetDataSourceItemModel {
	item := UnifiedLoggingFilterSetDataSourceItemModel{
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

	filterVals := make([]attr.Value, 0, len(api.Filters))
	for _, f := range api.Filters {
		filterVals = append(filterVals, types.ObjectValueMust(filterSetFilterAttrTypes, map[string]attr.Value{
			"uuid": types.StringValue(f.UUID),
			"name": types.StringValue(f.Name),
		}))
	}
	filterList, d := types.ListValue(types.ObjectType{AttrTypes: filterSetFilterAttrTypes}, filterVals)
	diags.Append(d...)
	item.Filters = filterList

	planVals := make([]attr.Value, 0, len(api.Plans))
	for _, p := range api.Plans {
		planVals = append(planVals, types.ObjectValueMust(filterSetPlanAttrTypes, map[string]attr.Value{
			"id":   types.StringValue(p.ID),
			"name": types.StringValue(p.Name),
		}))
	}
	planList, d := types.ListValue(types.ObjectType{AttrTypes: filterSetPlanAttrTypes}, planVals)
	diags.Append(d...)
	item.Plans = planList

	return item
}
