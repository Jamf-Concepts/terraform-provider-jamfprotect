package role

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// RoleResourceModel maps the resource schema data.
type RoleResourceModel struct {
	ID               types.String   `tfsdk:"id"`
	Name             types.String   `tfsdk:"name"`
	ReadPermissions  types.Set      `tfsdk:"read_permissions"`
	WritePermissions types.Set      `tfsdk:"write_permissions"`
	Created          types.String   `tfsdk:"created"`
	Updated          types.String   `tfsdk:"updated"`
	Timeouts         timeouts.Value `tfsdk:"timeouts"`
}
