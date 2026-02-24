// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"
	"slices"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ValidateConfig validates exception set configuration inputs.
func (r *ExceptionSetResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ExceptionSetResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Exceptions.IsNull() || data.Exceptions.IsUnknown() {
		return
	}

	var exceptions []exceptionModel
	resp.Diagnostics.Append(data.Exceptions.ElementsAs(ctx, &exceptions, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	seen := map[string]struct{}{}
	for _, exc := range exceptions {
		if exc.Type.IsNull() || exc.Type.IsUnknown() {
			continue
		}

		exceptionType := exc.Type.ValueString()
		subType := ""
		hasSubType := !exc.SubType.IsNull() && !exc.SubType.IsUnknown()
		if hasSubType {
			subType = exc.SubType.ValueString()
		}

		if exceptionTypeRequiresSubType(exceptionType) && (!hasSubType || subType == "") {
			resp.Diagnostics.AddError(
				"Missing exception subtype",
				"Exception types that require a subtype must specify sub_type.",
			)
		}

		if exceptionTypeForbidsSubType(exceptionType) && hasSubType && subType != "" {
			resp.Diagnostics.AddError(
				"Unexpected exception subtype",
				"Exception types that do not support subtypes must not set sub_type.",
			)
		}

		if options, ok := exceptionSubTypeOptions[exceptionType]; ok && hasSubType && subType != "" {
			if !slices.Contains(options, subType) {
				resp.Diagnostics.AddError(
					"Invalid exception subtype",
					"The specified sub_type is not valid for the selected exception type.",
				)
			}
		}

		key := exceptionType + "|" + subType
		if _, ok := seen[key]; ok {
			resp.Diagnostics.AddError(
				"Duplicate exception type/subtype",
				"Each exception type and subtype combination can only appear once.",
			)
		} else {
			seen[key] = struct{}{}
		}

		if exc.Rules.IsNull() {
			resp.Diagnostics.AddError(
				"Missing exception rules",
				"Each exception must include at least one rule.",
			)
			continue
		}

		if exc.Rules.IsUnknown() {
			continue
		}

		var rules []exceptionRuleModel
		resp.Diagnostics.Append(exc.Rules.ElementsAs(ctx, &rules, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if len(rules) == 0 {
			resp.Diagnostics.AddError(
				"Missing exception rules",
				"Each exception must include at least one rule.",
			)
			continue
		}

		allowedRuleTypes := exceptionTypeRuleTypeOptions[exceptionType]
		for _, rule := range rules {
			if rule.RuleType.IsNull() || rule.RuleType.IsUnknown() {
				continue
			}

			ruleType := rule.RuleType.ValueString()
			if len(allowedRuleTypes) > 0 && !slices.Contains(allowedRuleTypes, ruleType) {
				resp.Diagnostics.AddError(
					"Invalid rule type",
					"The rule type is not valid for the selected exception type.",
				)
			}

			if ruleType == "App Signing Info" {
				if !common.HasStringValue(rule.AppID) || !common.HasStringValue(rule.TeamID) {
					resp.Diagnostics.AddError(
						"Invalid App Signing Info rule",
						"App Signing Info rules require app_id and team_id.",
					)
				}
				continue
			}

			if !common.HasStringValue(rule.Value) {
				resp.Diagnostics.AddError(
					"Invalid rule value",
					"Rules other than App Signing Info require a value.",
				)
			}
		}
	}
}
