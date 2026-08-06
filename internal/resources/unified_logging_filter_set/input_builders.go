// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildInput converts the Terraform model into the service input.
func (r *UnifiedLoggingFilterSetResource) buildInput(ctx context.Context, data UnifiedLoggingFilterSetResourceModel, diags *diag.Diagnostics) *jamfprotect.UnifiedLoggingFilterSetInput {
	input := &jamfprotect.UnifiedLoggingFilterSetInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	}

	filters := common.SetToStrings(ctx, data.Filters, diags)
	if diags.HasError() {
		return nil
	}
	if filters == nil {
		filters = []string{}
	}
	input.Filters = filters

	return input
}

// validateFiltersExist ensures every unified logging filter UUID exists in Jamf Protect.
// The API accepts unknown UUIDs silently and creates a set with no members, so the
// check has to happen provider-side.
func (r *UnifiedLoggingFilterSetResource) validateFiltersExist(ctx context.Context, filters []string, diags *diag.Diagnostics) {
	if len(filters) == 0 {
		return
	}

	items, err := r.client.ListUnifiedLoggingFilters(ctx)
	if err != nil {
		diags.AddError("Error listing unified logging filters", err.Error())
		return
	}

	existing := map[string]bool{}
	for _, f := range items {
		existing[f.UUID] = true
	}

	missing := []string{}
	for _, id := range filters {
		if id == "" {
			continue
		}
		if !existing[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		diags.AddError(
			"Referenced unified logging filters missing",
			"This filter set references unified logging filters that do not exist in Jamf Protect: "+strings.Join(missing, ", ")+". Remove them from your configuration or recreate them before applying.",
		)
	}
}
