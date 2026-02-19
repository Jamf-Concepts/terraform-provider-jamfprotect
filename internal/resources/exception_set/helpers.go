// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"cmp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
)

// sortRuleModels returns a stable, sorted copy of rule models.
func sortRuleModels(rules []exceptionRuleModel) []exceptionRuleModel {
	result := make([]exceptionRuleModel, len(rules))
	copy(result, rules)
	slices.SortFunc(result, func(left, right exceptionRuleModel) int {
		return cmp.Compare(ruleModelSortKey(left), ruleModelSortKey(right))
	})
	return result
}

// ruleModelToObjectValue converts a rule model to an object value.
func ruleModelToObjectValue(rule exceptionRuleModel) attr.Value {
	return types.ObjectValueMust(
		exceptionRuleAttrTypes,
		map[string]attr.Value{
			"rule_type": rule.RuleType,
			"value":     rule.Value,
			"app_id":    rule.AppID,
			"team_id":   rule.TeamID,
		},
	)
}

// ruleModelSortKey builds a deterministic sort key for a rule model.
func ruleModelSortKey(rule exceptionRuleModel) string {
	parts := []string{
		common.StringValue(rule.RuleType),
		common.StringValue(rule.Value),
		common.StringValue(rule.AppID),
		common.StringValue(rule.TeamID),
	}
	return strings.Join(parts, "\x1f")
}
