// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildInput builds the API input from the resource model.
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
