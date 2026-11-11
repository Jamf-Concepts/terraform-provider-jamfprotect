// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PreventListSetResourceModel maps the resource schema data.
type PreventListSetResourceModel struct {
	ID           types.String   `tfsdk:"id"`
	Name         types.String   `tfsdk:"name"`
	Description  types.String   `tfsdk:"description"`
	PreventLists types.Set      `tfsdk:"prevent_lists"`
	Created      types.String   `tfsdk:"created"`
	Timeouts     timeouts.Value `tfsdk:"timeouts"`
}
