// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exceptionset

import (
	"context"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const exceptionSetFields = `
fragment ExceptionSetFields on ExceptionSet {
  uuid
  name
  description
  exceptions @skip(if: $minimal) {
    type
    value
    appSigningInfo {
      appId
      teamId
    }
    ignoreActivity
    analyticTypes
    analyticUuid
  }
  esExceptions @skip(if: $minimal) {
    type
    value
    appSigningInfo {
      appId
      teamId
    }
    ignoreActivity
    ignoreListType
    ignoreListSubType
    eventType
  }
  created
  updated
  managed
}
`

const createExceptionSetMutation = `
mutation createExceptionSet(
  $name: String!,
  $description: String,
  $exceptions: [ExceptionInput!]!,
  $esExceptions: [EsExceptionInput!]!,
  $minimal: Boolean!,
  $RBAC_Analytic: Boolean!,
  $RBAC_Plan: Boolean!
) {
  createExceptionSet(input: {
    name: $name,
    description: $description,
    exceptions: $exceptions,
    esExceptions: $esExceptions
  }) {
    ...ExceptionSetFields
  }
}
` + exceptionSetFields

const getExceptionSetQuery = `
query getExceptionSet(
  $uuid: ID!,
  $minimal: Boolean!,
  $RBAC_Analytic: Boolean!,
  $RBAC_Plan: Boolean!
) {
  getExceptionSet(uuid: $uuid) {
    ...ExceptionSetFields
  }
}
` + exceptionSetFields

const updateExceptionSetMutation = `
mutation updateExceptionSet(
  $uuid: ID!,
  $name: String!,
  $description: String,
  $exceptions: [ExceptionInput!]!,
  $esExceptions: [EsExceptionInput!]!,
  $minimal: Boolean!,
  $RBAC_Analytic: Boolean!,
  $RBAC_Plan: Boolean!
) {
  updateExceptionSet(uuid: $uuid, input: {
    name: $name,
    description: $description,
    exceptions: $exceptions,
    esExceptions: $esExceptions
  }) {
    ...ExceptionSetFields
  }
}
` + exceptionSetFields

const deleteExceptionSetMutation = `
mutation deleteExceptionSet($uuid: ID!) {
  deleteExceptionSet(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// Attribute type definitions for nested objects
// ---------------------------------------------------------------------------

// appSigningInfoAttrTypes defines the attribute types for app_signing_info.
var appSigningInfoAttrTypes = map[string]attr.Type{
	"app_id":  types.StringType,
	"team_id": types.StringType,
}

// exceptionAttrTypes defines the attribute types for exceptions.
var exceptionAttrTypes = map[string]attr.Type{
	"type":             types.StringType,
	"value":            types.StringType,
	"app_signing_info": types.ObjectType{AttrTypes: appSigningInfoAttrTypes},
	"ignore_activity":  types.StringType,
	"analytic_types":   types.ListType{ElemType: types.StringType},
	"analytic_uuid":    types.StringType,
}

// esExceptionAttrTypes defines the attribute types for es_exceptions.
var esExceptionAttrTypes = map[string]attr.Type{
	"type":                types.StringType,
	"value":               types.StringType,
	"app_signing_info":    types.ObjectType{AttrTypes: appSigningInfoAttrTypes},
	"ignore_activity":     types.StringType,
	"ignore_list_type":    types.StringType,
	"ignore_list_subtype": types.StringType,
	"event_type":          types.StringType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *ExceptionSetResource) buildVariables(ctx context.Context, data ExceptionSetResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":          data.Name.ValueString(),
		"minimal":       false,
		"RBAC_Analytic": true,
		"RBAC_Plan":     true,
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Build exceptions array
	vars["exceptions"] = buildExceptionsArray(ctx, data.Exceptions, diags)
	if diags.HasError() {
		return nil
	}

	// Build esExceptions array
	vars["esExceptions"] = buildEsExceptionsArray(ctx, data.EsExceptions, diags)
	if diags.HasError() {
		return nil
	}

	return vars
}

// buildExceptionsArray converts the exceptions list to API format.
func buildExceptionsArray(ctx context.Context, list types.List, diags *diag.Diagnostics) []map[string]any {
	if list.IsNull() || list.IsUnknown() {
		return []map[string]any{}
	}

	var exceptions []exceptionModel
	diags.Append(list.ElementsAs(ctx, &exceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]map[string]any, 0, len(exceptions))
	for _, exc := range exceptions {
		item := map[string]any{
			"type":           exc.Type.ValueString(),
			"ignoreActivity": exc.IgnoreActivity.ValueString(),
		}

		// Value is optional when using app_signing_info
		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item["value"] = exc.Value.ValueString()
		}

		// Handle app_signing_info if present
		if !exc.AppSigningInfo.IsNull() && !exc.AppSigningInfo.IsUnknown() {
			var appInfo appSigningInfoModel
			diags.Append(exc.AppSigningInfo.As(ctx, &appInfo, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() {
				item["appSigningInfo"] = map[string]any{
					"appId":  appInfo.AppId.ValueString(),
					"teamId": appInfo.TeamId.ValueString(),
				}
			}
		}

		// Handle analytic_types if present
		if !exc.AnalyticTypes.IsNull() && !exc.AnalyticTypes.IsUnknown() {
			item["analyticTypes"] = common.ListToStrings(ctx, exc.AnalyticTypes, diags)
		}

		// Handle analytic_uuid if present
		if !exc.AnalyticUuid.IsNull() && !exc.AnalyticUuid.IsUnknown() {
			item["analyticUuid"] = exc.AnalyticUuid.ValueString()
		}

		result = append(result, item)
	}

	return result
}

// buildEsExceptionsArray converts the es_exceptions list to API format.
func buildEsExceptionsArray(ctx context.Context, list types.List, diags *diag.Diagnostics) []map[string]any {
	if list.IsNull() || list.IsUnknown() {
		return []map[string]any{}
	}

	var esExceptions []esExceptionModel
	diags.Append(list.ElementsAs(ctx, &esExceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]map[string]any, 0, len(esExceptions))
	for _, exc := range esExceptions {
		item := map[string]any{
			"type":           exc.Type.ValueString(),
			"ignoreActivity": exc.IgnoreActivity.ValueString(),
		}

		// Value is optional
		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item["value"] = exc.Value.ValueString()
		}

		// Handle optional fields
		if !exc.IgnoreListType.IsNull() && !exc.IgnoreListType.IsUnknown() {
			item["ignoreListType"] = exc.IgnoreListType.ValueString()
		}
		if !exc.IgnoreListSubType.IsNull() && !exc.IgnoreListSubType.IsUnknown() {
			item["ignoreListSubType"] = exc.IgnoreListSubType.ValueString()
		}
		if !exc.EventType.IsNull() && !exc.EventType.IsUnknown() {
			item["eventType"] = exc.EventType.ValueString()
		}

		// Handle app_signing_info if present
		if !exc.AppSigningInfo.IsNull() && !exc.AppSigningInfo.IsUnknown() {
			var appInfo appSigningInfoModel
			diags.Append(exc.AppSigningInfo.As(ctx, &appInfo, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() {
				item["appSigningInfo"] = map[string]any{
					"appId":  appInfo.AppId.ValueString(),
					"teamId": appInfo.TeamId.ValueString(),
				}
			}
		}

		result = append(result, item)
	}

	return result
}

// apiToState maps the API response into the Terraform state model.
func (r *ExceptionSetResource) apiToState(ctx context.Context, data *ExceptionSetResourceModel, api exceptionSetResourceAPIModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Managed = types.BoolValue(api.Managed)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}

	// Convert exceptions array
	data.Exceptions = apiExceptionsToList(ctx, api.Exceptions, diags)

	// Convert esExceptions array
	data.EsExceptions = apiEsExceptionsToList(ctx, api.EsExceptions, diags)
}

// apiExceptionsToList converts API exceptions to a Terraform list.
func apiExceptionsToList(_ context.Context, apiExceptions []exceptionAPIModel, diags *diag.Diagnostics) types.List {
	if len(apiExceptions) == 0 {
		return types.ListValueMust(types.ObjectType{AttrTypes: exceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiExceptions))
	for _, apiExc := range apiExceptions {
		// Build app_signing_info object
		var appSigningInfoObj types.Object
		if apiExc.AppSigningInfo != nil {
			appSigningInfoObj = types.ObjectValueMust(
				appSigningInfoAttrTypes,
				map[string]attr.Value{
					"app_id":  types.StringValue(apiExc.AppSigningInfo.AppId),
					"team_id": types.StringValue(apiExc.AppSigningInfo.TeamId),
				},
			)
		} else {
			appSigningInfoObj = types.ObjectNull(appSigningInfoAttrTypes)
		}

		// Build analytic_types list
		var analyticTypesList types.List
		if len(apiExc.AnalyticTypes) > 0 {
			analyticTypesList = common.StringsToList(apiExc.AnalyticTypes)
		} else {
			analyticTypesList = types.ListNull(types.StringType)
		}

		// Handle optional value
		valueStr := types.StringNull()
		if apiExc.Value != "" {
			valueStr = types.StringValue(apiExc.Value)
		}

		// Handle optional analytic_uuid
		analyticUuidStr := types.StringNull()
		if apiExc.AnalyticUuid != "" {
			analyticUuidStr = types.StringValue(apiExc.AnalyticUuid)
		}

		obj := types.ObjectValueMust(
			exceptionAttrTypes,
			map[string]attr.Value{
				"type":             types.StringValue(apiExc.Type),
				"value":            valueStr,
				"app_signing_info": appSigningInfoObj,
				"ignore_activity":  types.StringValue(apiExc.IgnoreActivity),
				"analytic_types":   analyticTypesList,
				"analytic_uuid":    analyticUuidStr,
			},
		)
		elements = append(elements, obj)
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: exceptionAttrTypes}, elements)
	diags.Append(d...)
	return list
}

// apiEsExceptionsToList converts API esExceptions to a Terraform list.
func apiEsExceptionsToList(_ context.Context, apiEsExceptions []esExceptionAPIModel, diags *diag.Diagnostics) types.List {
	if len(apiEsExceptions) == 0 {
		return types.ListValueMust(types.ObjectType{AttrTypes: esExceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiEsExceptions))
	for _, apiExc := range apiEsExceptions {
		// Build app_signing_info object
		var appSigningInfoObj types.Object
		if apiExc.AppSigningInfo != nil {
			appSigningInfoObj = types.ObjectValueMust(
				appSigningInfoAttrTypes,
				map[string]attr.Value{
					"app_id":  types.StringValue(apiExc.AppSigningInfo.AppId),
					"team_id": types.StringValue(apiExc.AppSigningInfo.TeamId),
				},
			)
		} else {
			appSigningInfoObj = types.ObjectNull(appSigningInfoAttrTypes)
		}

		// Handle optional fields with null handling
		valueStr := types.StringNull()
		if apiExc.Value != "" {
			valueStr = types.StringValue(apiExc.Value)
		}

		ignoreListTypeStr := types.StringNull()
		if apiExc.IgnoreListType != "" {
			ignoreListTypeStr = types.StringValue(apiExc.IgnoreListType)
		}

		ignoreListSubTypeStr := types.StringNull()
		if apiExc.IgnoreListSubType != "" {
			ignoreListSubTypeStr = types.StringValue(apiExc.IgnoreListSubType)
		}

		eventTypeStr := types.StringNull()
		if apiExc.EventType != "" {
			eventTypeStr = types.StringValue(apiExc.EventType)
		}

		obj := types.ObjectValueMust(
			esExceptionAttrTypes,
			map[string]attr.Value{
				"type":                types.StringValue(apiExc.Type),
				"value":               valueStr,
				"app_signing_info":    appSigningInfoObj,
				"ignore_activity":     types.StringValue(apiExc.IgnoreActivity),
				"ignore_list_type":    ignoreListTypeStr,
				"ignore_list_subtype": ignoreListSubTypeStr,
				"event_type":          eventTypeStr,
			},
		)
		elements = append(elements, obj)
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: esExceptionAttrTypes}, elements)
	diags.Append(d...)
	return list
}
