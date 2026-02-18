// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// exceptionAttrTypes defines the attribute types for exceptions.
var exceptionAttrTypes = map[string]attr.Type{
	"type":            types.StringType,
	"value":           types.StringType,
	"app_id":          types.StringType,
	"team_id":         types.StringType,
	"ignore_activity": types.StringType,
	"analytic_types":  types.SetType{ElemType: types.StringType},
	"analytic_uuid":   types.StringType,
}

// esExceptionAttrTypes defines the attribute types for endpoint security exceptions.
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
