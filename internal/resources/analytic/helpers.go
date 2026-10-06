// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// smartGroupActionName is the analytic action driven by add_to_jamf_pro_smart_group.
const smartGroupActionName = "SmartGroup"

// smartGroupAction returns the SmartGroup action described by the Smart Group attributes, or nil
// when the analytic does not add devices to a Smart Group.
func smartGroupAction(addToSmartGroup types.Bool, identifier types.String) *analyticActionModel {
	if addToSmartGroup.IsNull() || !addToSmartGroup.ValueBool() {
		return nil
	}
	params := types.MapNull(types.StringType)
	if !identifier.IsNull() && identifier.ValueString() != "" {
		params = types.MapValueMust(types.StringType, map[string]attr.Value{"id": identifier})
	}
	return &analyticActionModel{Name: types.StringValue(smartGroupActionName), Parameters: params}
}

// mergeSmartGroupAction returns the analytic actions to send: the prior actions in their stored
// order, with the SmartGroup entry replaced or removed to match smartGroup, or appended when the
// prior actions have none. Actions other than SmartGroup are kept unchanged.
func mergeSmartGroupAction(ctx context.Context, prior types.List, smartGroup *analyticActionModel, diags *diag.Diagnostics) []analyticActionModel {
	var priorActions []analyticActionModel
	if !prior.IsNull() && !prior.IsUnknown() {
		diags.Append(prior.ElementsAs(ctx, &priorActions, false)...)
		if diags.HasError() {
			return nil
		}
	}

	merged := make([]analyticActionModel, 0, len(priorActions)+1)
	placed := false
	for _, action := range priorActions {
		if action.Name.ValueString() != smartGroupActionName {
			merged = append(merged, action)
			continue
		}
		if smartGroup != nil && !placed {
			merged = append(merged, *smartGroup)
			placed = true
		}
	}
	if smartGroup != nil && !placed {
		merged = append(merged, *smartGroup)
	}
	return merged
}

// analyticActionsToList converts analytic action models into a Terraform list value.
func analyticActionsToList(actions []analyticActionModel, diags *diag.Diagnostics) types.List {
	elemType := types.ObjectType{AttrTypes: analyticActionAttrTypes}
	values := make([]attr.Value, 0, len(actions))
	for _, action := range actions {
		values = append(values, types.ObjectValueMust(analyticActionAttrTypes, map[string]attr.Value{
			"name":       action.Name,
			"parameters": action.Parameters,
		}))
	}
	list, d := types.ListValue(elemType, values)
	diags.Append(d...)
	return list
}

// analyticActionsToInput converts analytic action models into API input, encoding parameters as
// a JSON object of strings ("{}" when there are none).
func analyticActionsToInput(ctx context.Context, actions []analyticActionModel, diags *diag.Diagnostics) []jamfprotect.AnalyticActionInput {
	inputs := make([]jamfprotect.AnalyticActionInput, 0, len(actions))
	for _, action := range actions {
		paramJSON := "{}"
		if !action.Parameters.IsNull() && !action.Parameters.IsUnknown() && len(action.Parameters.Elements()) > 0 {
			params := map[string]string{}
			diags.Append(action.Parameters.ElementsAs(ctx, &params, false)...)
			if diags.HasError() {
				return nil
			}
			encoded, err := json.Marshal(params)
			if err != nil {
				diags.AddError("Error encoding analytic action parameters", err.Error())
				return nil
			}
			paramJSON = string(encoded)
		}
		inputs = append(inputs, jamfprotect.AnalyticActionInput{
			Name:       action.Name.ValueString(),
			Parameters: paramJSON,
		})
	}
	return inputs
}

// apiAnalyticActionsToList maps API analytic actions into a Terraform list in API order.
func apiAnalyticActionsToList(api []jamfprotect.AnalyticAction, diags *diag.Diagnostics) types.List {
	actions := make([]analyticActionModel, 0, len(api))
	for _, action := range api {
		params, ok := analyticActionParametersToMap(action.Parameters, diags)
		if !ok {
			return types.ListNull(types.ObjectType{AttrTypes: analyticActionAttrTypes})
		}
		actions = append(actions, analyticActionModel{Name: types.StringValue(action.Name), Parameters: params})
	}
	return analyticActionsToList(actions, diags)
}

// analyticActionParametersToMap decodes an action's JSON parameters into a string map. Empty
// parameters map to null, and values that are not JSON strings are kept as their JSON text.
func analyticActionParametersToMap(raw string, diags *diag.Diagnostics) (types.Map, bool) {
	if raw == "" || raw == "{}" {
		return types.MapNull(types.StringType), true
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		diags.AddError("Error decoding analytic action parameters",
			fmt.Sprintf("Failed to parse parameters JSON %q: %s", raw, err.Error()))
		return types.MapNull(types.StringType), false
	}
	if len(decoded) == 0 {
		return types.MapNull(types.StringType), true
	}
	elements := make(map[string]attr.Value, len(decoded))
	for key, value := range decoded {
		var s string
		if err := json.Unmarshal(value, &s); err == nil {
			elements[key] = types.StringValue(s)
			continue
		}
		elements[key] = types.StringValue(string(value))
	}
	params, d := types.MapValue(types.StringType, elements)
	diags.Append(d...)
	return params, !d.HasError()
}

// priorAnalyticActions returns the analytic actions an update merges the SmartGroup action into:
// the actions in prior state, or the analytic's live actions when prior state predates the
// analytic_actions attribute and holds null.
func (r *AnalyticResource) priorAnalyticActions(ctx context.Context, id string, stateActions types.List, diags *diag.Diagnostics) types.List {
	if !stateActions.IsNull() {
		return stateActions
	}
	live, err := r.client.GetAnalytic(ctx, id)
	if err != nil {
		diags.AddError("Error reading analytic actions before update", fmt.Sprintf("analytic_actions is not in state and reading analytic %s failed: %s", id, err.Error()))
		return stateActions
	}
	if live == nil {
		diags.AddError("Error reading analytic actions before update", fmt.Sprintf("analytic_actions is not in state and analytic %s was not found.", id))
		return stateActions
	}
	return apiAnalyticActionsToList(live.AnalyticActions, diags)
}
