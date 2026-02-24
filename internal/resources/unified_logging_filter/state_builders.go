package unified_logging_filter

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the resource state.
func (r *UnifiedLoggingFilterResource) apiToState(_ context.Context, data *UnifiedLoggingFilterResourceModel, api jamfprotect.UnifiedLoggingFilter) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Filter = types.StringValue(api.Filter)
	data.Enabled = types.BoolValue(api.Enabled)
	data.Tags = common.StringsToSet(api.Tags)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Description = types.StringValue(api.Description)
}
