// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// filterSetFilterAttrTypes defines the attribute types for filter set member entries.
var filterSetFilterAttrTypes = map[string]attr.Type{
	"uuid": types.StringType,
	"name": types.StringType,
}

// filterSetPlanAttrTypes defines the attribute types for filter set plan entries.
var filterSetPlanAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
}
