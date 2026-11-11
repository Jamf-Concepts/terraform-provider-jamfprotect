// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// preventListSetListAttrTypes defines the attribute types for prevent list set member entries.
var preventListSetListAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
}

// preventListSetPlanAttrTypes defines the attribute types for prevent list set plan entries.
var preventListSetPlanAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
}
