// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PreventListResourceModel maps the resource schema data.
type PreventListResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Type        types.String   `tfsdk:"type"`
	Tags        types.List     `tfsdk:"tags"`
	List        types.List     `tfsdk:"list"`
	EntryCount  types.Int64    `tfsdk:"entry_count"`
	Created     types.String   `tfsdk:"created"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}
