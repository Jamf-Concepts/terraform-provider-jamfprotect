package change_management

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ChangeManagementResourceModel maps the resource schema data.
type ChangeManagementResourceModel struct {
	ID           types.String   `tfsdk:"id"`
	EnableFreeze types.Bool     `tfsdk:"enable_freeze"`
	Timeouts     timeouts.Value `tfsdk:"timeouts"`
}
