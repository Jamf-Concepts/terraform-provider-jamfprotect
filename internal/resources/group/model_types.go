package group

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// GroupResourceModel maps the resource schema data.
type GroupResourceModel struct {
	ID       types.String   `tfsdk:"id"`
	Name     types.String   `tfsdk:"name"`
	RoleIDs  types.Set      `tfsdk:"role_ids"`
	Created  types.String   `tfsdk:"created"`
	Updated  types.String   `tfsdk:"updated"`
	Timeouts timeouts.Value `tfsdk:"timeouts"`
}
