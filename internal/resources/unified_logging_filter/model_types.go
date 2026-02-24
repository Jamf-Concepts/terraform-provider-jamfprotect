package unified_logging_filter

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UnifiedLoggingFilterResourceModel maps the resource schema data.
type UnifiedLoggingFilterResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Filter      types.String   `tfsdk:"filter"`
	Enabled     types.Bool     `tfsdk:"enabled"`
	Tags        types.Set      `tfsdk:"tags"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}
