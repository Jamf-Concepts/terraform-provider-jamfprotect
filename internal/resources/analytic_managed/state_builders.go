// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// applyState maps the API response into the Terraform state model.
func (r *AnalyticManagedResource) applyState(_ context.Context, data *AnalyticManagedResourceModel, api jamfprotect.Analytic, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.SensorType = types.StringValue(mapSensorTypeAPIToUI(api.InputType))
	data.Filter = types.StringValue(normalizeFilterValue(api.Filter))
	data.Level = types.Int64Value(api.Level)
	data.Severity = types.StringValue(api.Severity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Label != "" {
		data.Label = types.StringValue(api.Label)
	} else {
		data.Label = types.StringNull()
	}

	data.Description = types.StringValue(api.Description)

	if api.LongDescription != "" {
		data.LongDescription = types.StringValue(api.LongDescription)
	} else {
		data.LongDescription = types.StringNull()
	}

	data.Tags = common.StringsToSet(api.Tags)
	data.Categories = common.StringsToSet(api.Categories)
	data.SnapshotFiles = common.StringsToSet(api.SnapshotFiles)

	data.TenantActions = apiActionsToSet(api.TenantActions, diags)

	if api.TenantSeverity != "" {
		data.TenantSeverity = types.StringValue(api.TenantSeverity)
	} else {
		data.TenantSeverity = types.StringNull()
	}

	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(analyticContextAttrTypes, map[string]attr.Value{
			"name":        types.StringValue(c.Name),
			"type":        types.StringValue(c.Type),
			"expressions": common.StringsToSet(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		data.ContextItem = types.SetValueMust(types.ObjectType{AttrTypes: analyticContextAttrTypes}, []attr.Value{})
	} else {
		ctxSet, d := types.SetValue(types.ObjectType{AttrTypes: analyticContextAttrTypes}, ctxVals)
		diags.Append(d...)
		data.ContextItem = ctxSet
	}

	data.Jamf = types.BoolValue(api.Jamf)

	if api.Remediation != "" {
		data.Remediation = types.StringValue(api.Remediation)
	} else {
		data.Remediation = types.StringNull()
	}
}

// apiActionsToSet maps API tenant actions into a Terraform set.
func apiActionsToSet(api []jamfprotect.AnalyticAction, diags *diag.Diagnostics) types.Set {
	if len(api) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: tenantActionAttrTypes}, []attr.Value{})
	}

	var actionVals []attr.Value
	for _, a := range api {
		paramVal := types.MapNull(types.StringType)
		if a.Parameters != "" && a.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(a.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", a.Parameters, err.Error()))
				return types.SetNull(types.ObjectType{AttrTypes: tenantActionAttrTypes})
			}
			if len(paramMap) > 0 {
				paramElements := make(map[string]attr.Value, len(paramMap))
				for k, v := range paramMap {
					paramElements[k] = types.StringValue(v)
				}
				mapVal, d := types.MapValue(types.StringType, paramElements)
				diags.Append(d...)
				paramVal = mapVal
			}
		}

		actionVals = append(actionVals, types.ObjectValueMust(tenantActionAttrTypes, map[string]attr.Value{
			"name":       types.StringValue(a.Name),
			"parameters": paramVal,
		}))
	}

	actionSet, d := types.SetValue(types.ObjectType{AttrTypes: tenantActionAttrTypes}, actionVals)
	diags.Append(d...)
	return actionSet
}

// mapSensorTypeAPIToUI maps an API sensor type to its UI label, or returns the API value unchanged
// if unknown (Jamf-managed analytics may use sensor types not exposed via the custom-analytic schema).
func mapSensorTypeAPIToUI(apiValue string) string {
	if ui, ok := sensorTypeAPIToUI[apiValue]; ok {
		return ui
	}
	return apiValue
}

// normalizeFilterValue strips Terraform's escaping of backslashes in filter strings.
func normalizeFilterValue(value string) string {
	if value == "" {
		return value
	}
	return strings.ReplaceAll(value, `\\`, `\`)
}
