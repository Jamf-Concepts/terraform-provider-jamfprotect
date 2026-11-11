// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// preventListSetAttrTypes defines the attribute types for the prevent list sets a list belongs to.
var preventListSetAttrTypes = map[string]attr.Type{
	"uuid": types.StringType,
	"name": types.StringType,
}
