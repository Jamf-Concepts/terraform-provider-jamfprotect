// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Attribute type definitions for nested objects
// ---------------------------------------------------------------------------

// exceptionAttrTypes defines the attribute types for exceptions.
var exceptionAttrTypes = map[string]attr.Type{
	"type":            types.StringType,
	"value":           types.StringType,
	"app_id":          types.StringType,
	"team_id":         types.StringType,
	"ignore_activity": types.StringType,
	"analytic_types":  types.ListType{ElemType: types.StringType},
	"analytic_uuid":   types.StringType,
}

// esExceptionAttrTypes defines the attribute types for es_exceptions.
var esExceptionAttrTypes = map[string]attr.Type{
	"type":                types.StringType,
	"value":               types.StringType,
	"app_id":              types.StringType,
	"team_id":             types.StringType,
	"ignore_activity":     types.StringType,
	"ignore_list_type":    types.StringType,
	"ignore_list_subtype": types.StringType,
	"event_type":          types.StringType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildInput converts the Terraform model into the service input.
func (r *ExceptionSetResource) buildInput(ctx context.Context, data ExceptionSetResourceModel, diags *diag.Diagnostics) *jamfprotect.ExceptionSetInput {
	input := &jamfprotect.ExceptionSetInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	// Build exceptions array.
	input.Exceptions = buildExceptionsArray(ctx, data.Exceptions, diags)
	if diags.HasError() {
		return nil
	}

	// Build esExceptions array.
	input.EsExceptions = buildEsExceptionsArray(ctx, data.EsExceptions, diags)
	if diags.HasError() {
		return nil
	}

	return input
}

// buildExceptionsArray converts the exceptions list to API format.
func buildExceptionsArray(ctx context.Context, set types.Set, diags *diag.Diagnostics) []jamfprotect.ExceptionInput {
	if set.IsNull() || set.IsUnknown() {
		return []jamfprotect.ExceptionInput{}
	}

	var exceptions []exceptionModel
	diags.Append(set.ElementsAs(ctx, &exceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]jamfprotect.ExceptionInput, 0, len(exceptions))
	for _, exc := range exceptions {
		item := jamfprotect.ExceptionInput{
			Type:           exc.Type.ValueString(),
			IgnoreActivity: exc.IgnoreActivity.ValueString(),
		}

		// Value is optional when using app_signing_info.
		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item.Value = exc.Value.ValueString()
		}

		if !exc.AppID.IsNull() && !exc.AppID.IsUnknown() && !exc.TeamID.IsNull() && !exc.TeamID.IsUnknown() {
			item.AppSigningInfo = &jamfprotect.AppSigningInfoInput{
				AppId:  exc.AppID.ValueString(),
				TeamId: exc.TeamID.ValueString(),
			}
		}

		// Handle analytic_types if present.
		if !exc.AnalyticTypes.IsNull() && !exc.AnalyticTypes.IsUnknown() {
			item.AnalyticTypes = common.ListToStrings(ctx, exc.AnalyticTypes, diags)
		}

		// Handle analytic_uuid if present.
		if !exc.AnalyticUuid.IsNull() && !exc.AnalyticUuid.IsUnknown() {
			item.AnalyticUuid = exc.AnalyticUuid.ValueString()
		}

		result = append(result, item)
	}

	return result
}

// buildEsExceptionsArray converts the es_exceptions list to API format.
func buildEsExceptionsArray(ctx context.Context, set types.Set, diags *diag.Diagnostics) []jamfprotect.EsExceptionInput {
	if set.IsNull() || set.IsUnknown() {
		return []jamfprotect.EsExceptionInput{}
	}

	var esExceptions []esExceptionModel
	diags.Append(set.ElementsAs(ctx, &esExceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]jamfprotect.EsExceptionInput, 0, len(esExceptions))
	for _, exc := range esExceptions {
		item := jamfprotect.EsExceptionInput{
			Type:           exc.Type.ValueString(),
			IgnoreActivity: exc.IgnoreActivity.ValueString(),
		}

		// Value is optional.
		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item.Value = exc.Value.ValueString()
		}

		// Handle optional fields.
		if !exc.IgnoreListType.IsNull() && !exc.IgnoreListType.IsUnknown() {
			item.IgnoreListType = exc.IgnoreListType.ValueString()
		}
		if !exc.IgnoreListSubType.IsNull() && !exc.IgnoreListSubType.IsUnknown() {
			item.IgnoreListSubType = exc.IgnoreListSubType.ValueString()
		}
		if !exc.EventType.IsNull() && !exc.EventType.IsUnknown() {
			item.EventType = exc.EventType.ValueString()
		}

		if !exc.AppID.IsNull() && !exc.AppID.IsUnknown() && !exc.TeamID.IsNull() && !exc.TeamID.IsUnknown() {
			item.AppSigningInfo = &jamfprotect.AppSigningInfoInput{
				AppId:  exc.AppID.ValueString(),
				TeamId: exc.TeamID.ValueString(),
			}
		}

		result = append(result, item)
	}

	return result
}

// apiToState maps the API response into the Terraform state model.
func (r *ExceptionSetResource) apiToState(ctx context.Context, data *ExceptionSetResourceModel, api jamfprotect.ExceptionSet, diags *diag.Diagnostics) {
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

	// Convert exceptions array.
	data.Exceptions = apiExceptionsToList(ctx, api.Exceptions, diags)

	// Convert esExceptions array.
	data.EsExceptions = apiEsExceptionsToList(ctx, api.EsExceptions, diags)
}

// apiExceptionsToList converts API exceptions to a Terraform list.
func apiExceptionsToList(_ context.Context, apiExceptions []jamfprotect.Exception, diags *diag.Diagnostics) types.Set {
	if len(apiExceptions) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: exceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiExceptions))
	for _, apiExc := range apiExceptions {
		appIDStr := types.StringNull()
		teamIDStr := types.StringNull()
		if apiExc.AppSigningInfo != nil {
			if apiExc.AppSigningInfo.AppId != "" {
				appIDStr = types.StringValue(apiExc.AppSigningInfo.AppId)
			}
			if apiExc.AppSigningInfo.TeamId != "" {
				teamIDStr = types.StringValue(apiExc.AppSigningInfo.TeamId)
			}
		}

		// Build analytic_types list.
		var analyticTypesList types.List
		if len(apiExc.AnalyticTypes) > 0 {
			analyticTypesList = common.StringsToList(apiExc.AnalyticTypes)
		} else {
			analyticTypesList = types.ListNull(types.StringType)
		}

		// Handle optional value.
		valueStr := types.StringNull()
		if apiExc.Value != "" {
			valueStr = types.StringValue(apiExc.Value)
		}

		// Handle optional analytic_uuid (via direct field or analytic reference).
		analyticUUID := apiExc.AnalyticUuid
		if analyticUUID == "" && apiExc.Analytic != nil {
			analyticUUID = apiExc.Analytic.UUID
		}
		analyticUuidStr := types.StringNull()
		if analyticUUID != "" {
			analyticUuidStr = types.StringValue(analyticUUID)
		}

		obj := types.ObjectValueMust(
			exceptionAttrTypes,
			map[string]attr.Value{
				"type":            types.StringValue(apiExc.Type),
				"value":           valueStr,
				"app_id":          appIDStr,
				"team_id":         teamIDStr,
				"ignore_activity": types.StringValue(apiExc.IgnoreActivity),
				"analytic_types":  analyticTypesList,
				"analytic_uuid":   analyticUuidStr,
			},
		)
		elements = append(elements, obj)
	}

	list, d := types.SetValue(types.ObjectType{AttrTypes: exceptionAttrTypes}, elements)
	diags.Append(d...)
	return list
}

// apiEsExceptionsToList converts API esExceptions to a Terraform list.
func apiEsExceptionsToList(_ context.Context, apiEsExceptions []jamfprotect.EsException, diags *diag.Diagnostics) types.Set {
	if len(apiEsExceptions) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: esExceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiEsExceptions))
	for _, apiExc := range apiEsExceptions {
		appIDStr := types.StringNull()
		teamIDStr := types.StringNull()
		if apiExc.AppSigningInfo != nil {
			if apiExc.AppSigningInfo.AppId != "" {
				appIDStr = types.StringValue(apiExc.AppSigningInfo.AppId)
			}
			if apiExc.AppSigningInfo.TeamId != "" {
				teamIDStr = types.StringValue(apiExc.AppSigningInfo.TeamId)
			}
		}

		// Handle optional fields with null handling.
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
				"app_id":              appIDStr,
				"team_id":             teamIDStr,
				"ignore_activity":     types.StringValue(apiExc.IgnoreActivity),
				"ignore_list_type":    ignoreListTypeStr,
				"ignore_list_subtype": ignoreListSubTypeStr,
				"event_type":          eventTypeStr,
			},
		)
		elements = append(elements, obj)
	}

	list, d := types.SetValue(types.ObjectType{AttrTypes: esExceptionAttrTypes}, elements)
	diags.Append(d...)
	return list
}
