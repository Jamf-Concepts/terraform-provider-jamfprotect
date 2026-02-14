// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildInput converts the Terraform model into the service input.
func (r *AnalyticResource) buildInput(ctx context.Context, data AnalyticResourceModel, diags *diag.Diagnostics) *jamfprotect.AnalyticInput {
	input := &jamfprotect.AnalyticInput{
		Name:      data.Name.ValueString(),
		InputType: data.SensorType.ValueString(),
		Filter:    data.Predicate.ValueString(),
		Level:     data.Level.ValueInt64(),
		Severity:  data.Severity.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	// Simple string lists.
	input.Tags = common.ListToStrings(ctx, data.Tags, diags)
	input.Categories = common.ListToStrings(ctx, data.Categories, diags)
	input.SnapshotFiles = common.ListToStrings(ctx, data.SnapshotFiles, diags)

	if !data.Actions.IsNull() {
		input.Actions = common.ListToStrings(ctx, data.Actions, diags)
	}

	// Analytic actions.
	actions := []jamfprotect.AnalyticActionInput{}
	if !data.AddToJamfProSmartGroup.IsNull() && data.AddToJamfProSmartGroup.ValueBool() {
		paramValue := "{}"
		if !data.JamfProSmartGroupIdentifier.IsNull() && data.JamfProSmartGroupIdentifier.ValueString() != "" {
			paramMap := map[string]string{"id": data.JamfProSmartGroupIdentifier.ValueString()}
			jsonBytes, err := json.Marshal(paramMap)
			if err != nil {
				diags.AddError("Error encoding Smart Group identifier", err.Error())
				return nil
			}
			paramValue = string(jsonBytes)
		}
		actions = append(actions, jamfprotect.AnalyticActionInput{
			Name:       "SmartGroup",
			Parameters: paramValue,
		})
	}
	input.AnalyticActions = actions

	// Context.
	var ctxEntries []jamfprotect.AnalyticContextInput
	if !data.ContextItem.IsNull() {
		var contextModels []analyticContextModel
		diags.Append(data.ContextItem.ElementsAs(ctx, &contextModels, false)...)
		for _, c := range contextModels {
			ctxEntries = append(ctxEntries, jamfprotect.AnalyticContextInput{
				Name:  c.Name.ValueString(),
				Type:  c.Type.ValueString(),
				Exprs: common.ListToStrings(ctx, c.Expressions, diags),
			})
		}
	}
	if ctxEntries == nil {
		ctxEntries = []jamfprotect.AnalyticContextInput{}
	}
	input.Context = ctxEntries

	return input
}

// apiToState maps the API response into the Terraform state model.
func (r *AnalyticResource) apiToState(_ context.Context, data *AnalyticResourceModel, api jamfprotect.Analytic, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.SensorType = types.StringValue(api.InputType)
	data.Predicate = types.StringValue(api.Filter)
	data.Level = types.Int64Value(api.Level)
	data.Severity = types.StringValue(api.Severity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Label != "" {
		data.Label = types.StringValue(api.Label)
	} else {
		data.Label = types.StringNull()
	}

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.LongDescription != "" {
		data.LongDescription = types.StringValue(api.LongDescription)
	} else {
		data.LongDescription = types.StringNull()
	}

	data.Tags = common.StringsToList(api.Tags)
	data.Categories = common.StringsToList(api.Categories)
	data.SnapshotFiles = common.StringsToList(api.SnapshotFiles)

	// actions is Optional — preserve null when the API returns an empty array
	// so the plan doesn't show a diff from null → [].
	if len(api.Actions) == 0 {
		data.Actions = types.ListNull(types.StringType)
	} else {
		data.Actions = common.StringsToList(api.Actions)
	}

	data.AddToJamfProSmartGroup = types.BoolValue(false)
	data.JamfProSmartGroupIdentifier = types.StringNull()
	for _, action := range api.AnalyticActions {
		if action.Name != "SmartGroup" {
			continue
		}
		data.AddToJamfProSmartGroup = types.BoolValue(true)
		if action.Parameters != "" && action.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(action.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding Smart Group parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", action.Parameters, err.Error()))
				break
			}
			if id, ok := paramMap["id"]; ok && id != "" {
				data.JamfProSmartGroupIdentifier = types.StringValue(id)
			}
		}
		break
	}

	data.TenantActions = apiActionsToList(api.TenantActions, true, diags)

	if api.TenantSeverity != "" {
		data.TenantSeverity = types.StringValue(api.TenantSeverity)
	} else {
		data.TenantSeverity = types.StringNull()
	}

	// Context.
	ctxAttrTypes := map[string]attr.Type{
		"name":        types.StringType,
		"type":        types.StringType,
		"expressions": types.ListType{ElemType: types.StringType},
	}
	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(ctxAttrTypes, map[string]attr.Value{
			"name":        types.StringValue(c.Name),
			"type":        types.StringValue(c.Type),
			"expressions": common.StringsToList(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		data.ContextItem = types.ListValueMust(types.ObjectType{AttrTypes: ctxAttrTypes}, []attr.Value{})
	} else {
		ctxList, d := types.ListValue(types.ObjectType{AttrTypes: ctxAttrTypes}, ctxVals)
		diags.Append(d...)
		data.ContextItem = ctxList
	}

	data.Jamf = types.BoolValue(api.Jamf)

	if api.Remediation != "" {
		data.Remediation = types.StringValue(api.Remediation)
	} else {
		data.Remediation = types.StringNull()
	}
}

// apiActionsToList maps AnalyticActions to a Terraform list of objects. When nullOnNil is true and the API field is absent/null,
// return a null list to preserve provider semantics (avoiding diffs from null → []).
func apiActionsToList(api []jamfprotect.AnalyticAction, nullOnNil bool, diags *diag.Diagnostics) types.List {
	actionAttrTypes := map[string]attr.Type{
		"name":       types.StringType,
		"parameters": types.MapType{ElemType: types.StringType},
	}

	if api == nil {
		if nullOnNil {
			return types.ListNull(types.ObjectType{AttrTypes: actionAttrTypes})
		}
		return types.ListValueMust(types.ObjectType{AttrTypes: actionAttrTypes}, []attr.Value{})
	}

	if len(api) == 0 {
		return types.ListValueMust(types.ObjectType{AttrTypes: actionAttrTypes}, []attr.Value{})
	}

	var actionVals []attr.Value
	for _, a := range api {
		paramVal := types.MapNull(types.StringType)
		if a.Parameters != "" && a.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(a.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", a.Parameters, err.Error()))
				return types.ListNull(types.ObjectType{AttrTypes: actionAttrTypes})
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

		actionVals = append(actionVals, types.ObjectValueMust(actionAttrTypes, map[string]attr.Value{
			"name":       types.StringValue(a.Name),
			"parameters": paramVal,
		}))
	}

	actionList, d := types.ListValue(types.ObjectType{AttrTypes: actionAttrTypes}, actionVals)
	diags.Append(d...)
	return actionList
}
