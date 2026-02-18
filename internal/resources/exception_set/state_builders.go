// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// applyState maps the API response into the Terraform state model.
func (r *ExceptionSetResource) applyState(ctx context.Context, data *ExceptionSetResourceModel, api jamfprotect.ExceptionSet, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Managed = types.BoolValue(api.Managed)
	data.Description = types.StringValue(api.Description)

	if api.Description == "" {
		data.Description = types.StringValue("")
	}

	data.Exceptions = exceptionsToState(ctx, api.Exceptions, diags)
	data.EsExceptions = esExceptionsToState(ctx, api.EsExceptions, diags)
}

// exceptionsToState converts API exceptions to a Terraform set.
func exceptionsToState(_ context.Context, apiExceptions []jamfprotect.Exception, diags *diag.Diagnostics) types.Set {
	if len(apiExceptions) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: exceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiExceptions))
	for _, apiExc := range apiExceptions {
		appIDValue := common.StringValueOrNullValue("")
		teamIDValue := common.StringValueOrNullValue("")
		if apiExc.AppSigningInfo != nil {
			appIDValue = common.StringValueOrNullValue(apiExc.AppSigningInfo.AppId)
			teamIDValue = common.StringValueOrNullValue(apiExc.AppSigningInfo.TeamId)
		}

		analyticTypesValue := types.SetNull(types.StringType)
		if len(apiExc.AnalyticTypes) > 0 {
			analyticTypesValue = common.StringsToSet(apiExc.AnalyticTypes)
		}

		analyticUUID := apiExc.AnalyticUuid
		if analyticUUID == "" && apiExc.Analytic != nil {
			analyticUUID = apiExc.Analytic.UUID
		}

		obj := types.ObjectValueMust(
			exceptionAttrTypes,
			map[string]attr.Value{
				"type":            types.StringValue(mapExceptionTypeAPIToUI(apiExc.Type, diags)),
				"value":           common.StringValueOrNullValue(apiExc.Value),
				"app_id":          appIDValue,
				"team_id":         teamIDValue,
				"ignore_activity": types.StringValue(apiExc.IgnoreActivity),
				"analytic_types":  analyticTypesValue,
				"analytic_uuid":   common.StringValueOrNullValue(analyticUUID),
			},
		)
		elements = append(elements, obj)
	}

	setValue, d := types.SetValue(types.ObjectType{AttrTypes: exceptionAttrTypes}, elements)
	diags.Append(d...)
	return setValue
}

// esExceptionsToState converts API endpoint security exceptions to a Terraform set.
func esExceptionsToState(_ context.Context, apiExceptions []jamfprotect.EsException, diags *diag.Diagnostics) types.Set {
	if len(apiExceptions) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: esExceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(apiExceptions))
	for _, apiExc := range apiExceptions {
		appIDValue := common.StringValueOrNullValue("")
		teamIDValue := common.StringValueOrNullValue("")
		if apiExc.AppSigningInfo != nil {
			appIDValue = common.StringValueOrNullValue(apiExc.AppSigningInfo.AppId)
			teamIDValue = common.StringValueOrNullValue(apiExc.AppSigningInfo.TeamId)
		}

		obj := types.ObjectValueMust(
			esExceptionAttrTypes,
			map[string]attr.Value{
				"type":                types.StringValue(mapEsExceptionTypeAPIToUI(apiExc.Type, diags)),
				"value":               common.StringValueOrNullValue(apiExc.Value),
				"app_id":              appIDValue,
				"team_id":             teamIDValue,
				"ignore_activity":     types.StringValue(apiExc.IgnoreActivity),
				"ignore_list_type":    common.StringValueOrNullValue(apiExc.IgnoreListType),
				"ignore_list_subtype": common.StringValueOrNullValue(apiExc.IgnoreListSubType),
				"event_type":          common.StringValueOrNullValue(apiExc.EventType),
			},
		)
		elements = append(elements, obj)
	}

	setValue, d := types.SetValue(types.ObjectType{AttrTypes: esExceptionAttrTypes}, elements)
	diags.Append(d...)
	return setValue
}
