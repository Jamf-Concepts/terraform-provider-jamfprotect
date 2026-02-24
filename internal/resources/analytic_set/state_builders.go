package analytic_set

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// applyState maps the API response into the Terraform state model.
func (r *AnalyticSetResource) applyState(_ context.Context, data *AnalyticSetResourceModel, api jamfprotect.AnalyticSet, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Managed = types.BoolValue(api.Managed)

	data.Description = types.StringValue(api.Description)

	analyticUUIDs := make([]string, 0, len(api.Analytics))
	for _, a := range api.Analytics {
		analyticUUIDs = append(analyticUUIDs, a.UUID)
	}
	data.Analytics = common.StringsToSet(analyticUUIDs)
}

// analyticSetAPIToDataSourceItem maps a Jamf Protect analytic set to AnalyticSetDataSourceItemModel.
func analyticSetAPIToDataSourceItem(api jamfprotect.AnalyticSet, diags *diag.Diagnostics) AnalyticSetDataSourceItemModel {
	item := AnalyticSetDataSourceItemModel{
		UUID:    types.StringValue(api.UUID),
		Name:    types.StringValue(api.Name),
		Created: types.StringValue(api.Created),
		Updated: types.StringValue(api.Updated),
		Managed: types.BoolValue(api.Managed),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	item.Types = common.StringsToList(api.Types)

	analyticVals := make([]attr.Value, 0, len(api.Analytics))
	for _, a := range api.Analytics {
		analyticVals = append(analyticVals, types.ObjectValueMust(analyticSetAnalyticAttrTypes, map[string]attr.Value{
			"uuid": types.StringValue(a.UUID),
			"name": types.StringValue(a.Name),
			"jamf": types.BoolValue(a.Jamf),
		}))
	}
	if len(analyticVals) == 0 {
		item.Analytics = types.ListValueMust(types.ObjectType{AttrTypes: analyticSetAnalyticAttrTypes}, []attr.Value{})
	} else {
		analyticList, d := types.ListValue(types.ObjectType{AttrTypes: analyticSetAnalyticAttrTypes}, analyticVals)
		diags.Append(d...)
		item.Analytics = analyticList
	}

	planVals := make([]attr.Value, 0, len(api.Plans))
	for _, p := range api.Plans {
		planVals = append(planVals, types.ObjectValueMust(analyticSetPlanAttrTypes, map[string]attr.Value{
			"id":   types.StringValue(p.ID),
			"name": types.StringValue(p.Name),
		}))
	}
	if len(planVals) == 0 {
		item.Plans = types.ListValueMust(types.ObjectType{AttrTypes: analyticSetPlanAttrTypes}, []attr.Value{})
	} else {
		planList, d := types.ListValue(types.ObjectType{AttrTypes: analyticSetPlanAttrTypes}, planVals)
		diags.Append(d...)
		item.Plans = planList
	}

	return item
}
