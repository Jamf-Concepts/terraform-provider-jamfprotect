// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ModifyPlan normalizes exception rules to a stable order to avoid diffs.
func (r *ExceptionSetResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan ExceptionSetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Exceptions.IsNull() || plan.Exceptions.IsUnknown() {
		return
	}

	var exceptions []exceptionModel
	resp.Diagnostics.Append(plan.Exceptions.ElementsAs(ctx, &exceptions, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	elements := make([]attr.Value, 0, len(exceptions))
	for _, exc := range exceptions {
		rulesValue := attr.Value(exc.Rules)
		if !exc.Rules.IsNull() && !exc.Rules.IsUnknown() {
			var rules []exceptionRuleModel
			resp.Diagnostics.Append(exc.Rules.ElementsAs(ctx, &rules, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			sortedRules := sortRuleModels(rules)
			ruleValues := make([]attr.Value, 0, len(sortedRules))
			for _, rule := range sortedRules {
				ruleValues = append(ruleValues, ruleModelToObjectValue(rule))
			}
			listValue, d := types.ListValue(types.ObjectType{AttrTypes: exceptionRuleAttrTypes}, ruleValues)
			resp.Diagnostics.Append(d...)
			rulesValue = listValue
		}

		obj := types.ObjectValueMust(
			exceptionAttrTypes,
			map[string]attr.Value{
				"type":     exc.Type,
				"sub_type": exc.SubType,
				"rules":    rulesValue,
			},
		)
		elements = append(elements, obj)
	}

	setValue, d := types.SetValue(types.ObjectType{AttrTypes: exceptionAttrTypes}, elements)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Exceptions = setValue
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}
