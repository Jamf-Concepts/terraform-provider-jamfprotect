// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// analyticContextAttrTypes defines the attribute types for the Analytic Context block.
var analyticContextAttrTypes = map[string]attr.Type{
	"name":        types.StringType,
	"type":        types.StringType,
	"expressions": types.SetType{ElemType: types.StringType},
}

// analyticActionAttrTypes defines the attribute types for an analytic action object. It shares
// the shape of a tenant action.
var analyticActionAttrTypes = tenantActionAttrTypes

// tenantActionAttrTypes defines the attribute types for the Tenant Action block within an AnalyticAction.
var tenantActionAttrTypes = map[string]attr.Type{
	"name":       types.StringType,
	"parameters": types.MapType{ElemType: types.StringType},
}
