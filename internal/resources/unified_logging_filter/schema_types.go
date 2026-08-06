// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// filterSetAttrTypes defines the attribute types for the filter set entries a filter belongs to.
var filterSetAttrTypes = map[string]attr.Type{
	"uuid": types.StringType,
	"name": types.StringType,
}
