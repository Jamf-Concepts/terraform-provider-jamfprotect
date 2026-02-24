// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// exceptionRuleAttrTypes defines the attribute types for exception rules.
var exceptionRuleAttrTypes = map[string]attr.Type{
	"rule_type": types.StringType,
	"value":     types.StringType,
	"app_id":    types.StringType,
	"team_id":   types.StringType,
}

// exceptionAttrTypes defines the attribute types for exception entries.
var exceptionAttrTypes = map[string]attr.Type{
	"type":     types.StringType,
	"sub_type": types.StringType,
	"rules": types.ListType{ElemType: types.ObjectType{
		AttrTypes: exceptionRuleAttrTypes,
	}},
}
