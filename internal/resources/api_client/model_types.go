// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ApiClientResourceModel maps the resource schema data.
type ApiClientResourceModel struct {
	ID       types.String   `tfsdk:"id"`
	Name     types.String   `tfsdk:"name"`
	RoleIDs  types.Set      `tfsdk:"role_ids"`
	Password types.String   `tfsdk:"password"`
	Created  types.String   `tfsdk:"created"`
	Timeouts timeouts.Value `tfsdk:"timeouts"`
}
