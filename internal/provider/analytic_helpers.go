// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// GraphQL queries – stripped of the @skip/@include directives the browser uses
// ---------------------------------------------------------------------------

const analyticFields = `
fragment AnalyticFields on Analytic {
  uuid
  name
  inputType
  filter
  description
  created
  updated
  actions
  analyticActions {
    name
    parameters
  }
  tags
  level
  severity
  snapshotFiles
  context {
    name
    type
    exprs
  }
  categories
}
`

const createAnalyticMutation = `
mutation createAnalytic(
  $name: String!,
  $inputType: String!,
  $description: String!,
  $actions: [String],
  $analyticActions: [AnalyticActionsInput]!,
  $tags: [String]!,
  $categories: [String]!,
  $filter: String!,
  $context: [AnalyticContextInput]!,
  $level: Int!,
  $severity: SEVERITY!,
  $snapshotFiles: [String]!
) {
  createAnalytic(input: {
    name: $name,
    inputType: $inputType,
    description: $description,
    actions: $actions,
    analyticActions: $analyticActions,
    tags: $tags,
    categories: $categories,
    filter: $filter,
    context: $context,
    level: $level,
    severity: $severity,
    snapshotFiles: $snapshotFiles
  }) {
    ...AnalyticFields
  }
}
` + analyticFields

const getAnalyticQuery = `
query getAnalytic($uuid: ID!) {
  getAnalytic(uuid: $uuid) {
    ...AnalyticFields
  }
}
` + analyticFields

const updateAnalyticMutation = `
mutation updateAnalytic(
  $uuid: ID!,
  $name: String!,
  $inputType: String!,
  $description: String!,
  $actions: [String],
  $analyticActions: [AnalyticActionsInput]!,
  $tags: [String]!,
  $categories: [String]!,
  $filter: String!,
  $context: [AnalyticContextInput]!,
  $level: Int!,
  $severity: SEVERITY,
  $snapshotFiles: [String]!
) {
  updateAnalytic(uuid: $uuid, input: {
    name: $name,
    inputType: $inputType,
    description: $description,
    actions: $actions,
    analyticActions: $analyticActions,
    categories: $categories,
    tags: $tags,
    filter: $filter,
    context: $context,
    level: $level,
    severity: $severity,
    snapshotFiles: $snapshotFiles
  }) {
    ...AnalyticFields
  }
}
` + analyticFields

const deleteAnalyticMutation = `
mutation deleteAnalytic($uuid: ID!) {
  deleteAnalytic(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *AnalyticResource) buildVariables(ctx context.Context, data AnalyticResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":      data.Name.ValueString(),
		"inputType": data.InputType.ValueString(),
		"filter":    data.Filter.ValueString(),
		"level":     data.Level.ValueInt64(),
		"severity":  data.Severity.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Simple string lists.
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	vars["categories"] = listToStrings(ctx, data.Categories, diags)
	vars["snapshotFiles"] = listToStrings(ctx, data.SnapshotFiles, diags)

	if !data.Actions.IsNull() {
		vars["actions"] = listToStrings(ctx, data.Actions, diags)
	}

	// Analytic actions.
	var actions []map[string]any
	if !data.AnalyticActions.IsNull() {
		var actionModels []analyticActionModel
		diags.Append(data.AnalyticActions.ElementsAs(ctx, &actionModels, false)...)
		for _, a := range actionModels {
			m := map[string]any{"name": a.Name.ValueString()}
			if !a.Parameters.IsNull() && len(a.Parameters.Elements()) > 0 {
				// Convert the map to a JSON-encoded string for the API.
				paramMap := make(map[string]string, len(a.Parameters.Elements()))
				diags.Append(a.Parameters.ElementsAs(ctx, &paramMap, false)...)
				jsonBytes, err := json.Marshal(paramMap)
				if err != nil {
					diags.AddError("Error encoding parameters", err.Error())
					return nil
				}
				m["parameters"] = string(jsonBytes)
			} else {
				// The API requires parameters as AWSJSON! (non-null),
				// so send an empty JSON object when no parameters are provided.
				m["parameters"] = "{}"
			}
			actions = append(actions, m)
		}
	}
	if actions == nil {
		actions = []map[string]any{}
	}
	vars["analyticActions"] = actions

	// Context.
	var ctxEntries []map[string]any
	if !data.Context.IsNull() {
		var contextModels []analyticContextModel
		diags.Append(data.Context.ElementsAs(ctx, &contextModels, false)...)
		for _, c := range contextModels {
			ctxEntries = append(ctxEntries, map[string]any{
				"name":  c.Name.ValueString(),
				"type":  c.Type.ValueString(),
				"exprs": listToStrings(ctx, c.Exprs, diags),
			})
		}
	}
	if ctxEntries == nil {
		ctxEntries = []map[string]any{}
	}
	vars["context"] = ctxEntries

	return vars
}

// apiToState maps the API response into the Terraform state model.
func (r *AnalyticResource) apiToState(_ context.Context, data *AnalyticResourceModel, api analyticAPIModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.InputType = types.StringValue(api.InputType)
	data.Filter = types.StringValue(api.Filter)
	data.Level = types.Int64Value(api.Level)
	data.Severity = types.StringValue(api.Severity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	data.Tags = stringsToList(api.Tags)
	data.Categories = stringsToList(api.Categories)
	data.SnapshotFiles = stringsToList(api.SnapshotFiles)

	// actions is Optional — preserve null when the API returns an empty array
	// so the plan doesn't show a diff from null → [].
	if len(api.Actions) == 0 {
		data.Actions = types.ListNull(types.StringType)
	} else {
		data.Actions = stringsToList(api.Actions)
	}

	// Analytic actions.
	actionAttrTypes := map[string]attr.Type{
		"name":       types.StringType,
		"parameters": types.MapType{ElemType: types.StringType},
	}
	var actionVals []attr.Value
	for _, a := range api.AnalyticActions {
		paramVal := types.MapNull(types.StringType)
		if a.Parameters != "" && a.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(a.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", a.Parameters, err.Error()))
				return
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
	if len(actionVals) == 0 {
		data.AnalyticActions = types.ListValueMust(types.ObjectType{AttrTypes: actionAttrTypes}, []attr.Value{})
	} else {
		actionList, d := types.ListValue(types.ObjectType{AttrTypes: actionAttrTypes}, actionVals)
		diags.Append(d...)
		data.AnalyticActions = actionList
	}

	// Context.
	ctxAttrTypes := map[string]attr.Type{
		"name":  types.StringType,
		"type":  types.StringType,
		"exprs": types.ListType{ElemType: types.StringType},
	}
	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(ctxAttrTypes, map[string]attr.Value{
			"name":  types.StringValue(c.Name),
			"type":  types.StringValue(c.Type),
			"exprs": stringsToList(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		data.Context = types.ListValueMust(types.ObjectType{AttrTypes: ctxAttrTypes}, []attr.Value{})
	} else {
		ctxList, d := types.ListValue(types.ObjectType{AttrTypes: ctxAttrTypes}, ctxVals)
		diags.Append(d...)
		data.Context = ctxList
	}
}
