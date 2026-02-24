// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
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

	data.Exceptions = exceptionsToState(ctx, api.Exceptions, api.EsExceptions, diags)
}

// exceptionsToState converts API exceptions into Terraform exception entries.
func exceptionsToState(_ context.Context, apiExceptions []jamfprotect.Exception, apiEsExceptions []jamfprotect.EsException, diags *diag.Diagnostics) types.Set {
	state := map[string][]exceptionRuleModel{}
	meta := map[string][2]string{}

	for _, apiExc := range apiExceptions {
		analyticUUID := apiExc.AnalyticUuid
		if analyticUUID == "" && apiExc.Analytic != nil {
			analyticUUID = apiExc.Analytic.UUID
		}

		exceptionType, subType, ok := mapApiExceptionType(apiExc.IgnoreActivity, apiExc.AnalyticTypes, analyticUUID)
		if !ok {
			diags.AddError(
				"Unsupported exception mapping",
				"Unable to map API exception to a UI exception type.",
			)
			continue
		}

		ruleType := mapRuleTypeAPIToUI(apiExc.Type, diags)
		ruleValue := types.StringNull()
		if apiExc.Value != "" {
			ruleValue = types.StringValue(apiExc.Value)
		}
		appIDValue := types.StringNull()
		teamIDValue := types.StringNull()
		if apiExc.AppSigningInfo != nil {
			if apiExc.AppSigningInfo.AppId != "" {
				appIDValue = types.StringValue(apiExc.AppSigningInfo.AppId)
			}
			if apiExc.AppSigningInfo.TeamId != "" {
				teamIDValue = types.StringValue(apiExc.AppSigningInfo.TeamId)
			}
		}

		rule := exceptionRuleModel{
			RuleType: types.StringValue(ruleType),
			Value:    ruleValue,
			AppID:    appIDValue,
			TeamID:   teamIDValue,
		}

		key := exceptionType + "|" + subType
		state[key] = append(state[key], rule)
		meta[key] = [2]string{exceptionType, subType}
	}

	for _, apiExc := range apiEsExceptions {
		exceptionType, subType, ok := mapApiEsExceptionType(apiExc.IgnoreActivity, apiExc.IgnoreListType, apiExc.IgnoreListSubType, apiExc.EventType)
		if !ok {
			diags.AddError(
				"Unsupported ES exception mapping",
				"Unable to map API ES exception to a UI exception type.",
			)
			continue
		}

		ruleType := mapEsRuleTypeAPIToUI(apiExc.Type, diags)
		ruleValue := types.StringNull()
		if apiExc.Value != "" {
			ruleValue = types.StringValue(apiExc.Value)
		}
		appIDValue := types.StringNull()
		teamIDValue := types.StringNull()
		if apiExc.AppSigningInfo != nil {
			if apiExc.AppSigningInfo.AppId != "" {
				appIDValue = types.StringValue(apiExc.AppSigningInfo.AppId)
			}
			if apiExc.AppSigningInfo.TeamId != "" {
				teamIDValue = types.StringValue(apiExc.AppSigningInfo.TeamId)
			}
		}

		rule := exceptionRuleModel{
			RuleType: types.StringValue(ruleType),
			Value:    ruleValue,
			AppID:    appIDValue,
			TeamID:   teamIDValue,
		}

		key := exceptionType + "|" + subType
		state[key] = append(state[key], rule)
		meta[key] = [2]string{exceptionType, subType}
	}

	if len(state) == 0 {
		return types.SetValueMust(types.ObjectType{AttrTypes: exceptionAttrTypes}, []attr.Value{})
	}

	elements := make([]attr.Value, 0, len(state))
	for key, rules := range state {
		info := meta[key]
		sortedRules := sortRuleModels(rules)
		ruleValues := make([]attr.Value, 0, len(sortedRules))
		for _, rule := range sortedRules {
			ruleValues = append(ruleValues, ruleModelToObjectValue(rule))
		}
		rulesList, d := types.ListValue(types.ObjectType{AttrTypes: exceptionRuleAttrTypes}, ruleValues)
		diags.Append(d...)
		obj := types.ObjectValueMust(
			exceptionAttrTypes,
			map[string]attr.Value{
				"type":     types.StringValue(info[0]),
				"sub_type": common.StringValueOrNullValue(info[1]),
				"rules":    rulesList,
			},
		)
		elements = append(elements, obj)
	}

	setValue, d := types.SetValue(types.ObjectType{AttrTypes: exceptionAttrTypes}, elements)
	diags.Append(d...)
	return setValue
}
