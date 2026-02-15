// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *UnifiedLoggingFilterResource) buildInput(ctx context.Context, data UnifiedLoggingFilterResourceModel, diags *diag.Diagnostics) *jamfprotect.UnifiedLoggingFilterInput {
	input := &jamfprotect.UnifiedLoggingFilterInput{
		Name:    data.Name.ValueString(),
		Filter:  data.Filter.ValueString(),
		Enabled: data.Enabled.ValueBool(),
		Tags:    common.SetToStrings(ctx, data.Tags, diags),
	}
	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}
	return input
}

func (r *UnifiedLoggingFilterResource) apiToState(_ context.Context, data *UnifiedLoggingFilterResourceModel, api jamfprotect.UnifiedLoggingFilter, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Filter = types.StringValue(api.Filter)
	data.Enabled = types.BoolValue(api.Enabled)
	data.Tags = common.StringsToSet(api.Tags)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
