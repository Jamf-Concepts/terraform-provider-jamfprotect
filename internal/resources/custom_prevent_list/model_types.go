package custom_prevent_list

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CustomPreventListResourceModel maps the resource schema data.
type CustomPreventListResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	PreventType types.String   `tfsdk:"prevent_type"`
	ListData    types.List     `tfsdk:"list_data"`
	EntryCount  types.Int64    `tfsdk:"entry_count"`
	Created     types.String   `tfsdk:"created"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}
