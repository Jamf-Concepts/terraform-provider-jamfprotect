// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// analyticSetAnalyticAttrTypes defines the attribute types for analytic set analytics entries.
var analyticSetAnalyticAttrTypes = map[string]attr.Type{
	"uuid": types.StringType,
	"name": types.StringType,
	"jamf": types.BoolType,
}

// analyticSetPlanAttrTypes defines the attribute types for analytic set plan entries.
var analyticSetPlanAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
}
