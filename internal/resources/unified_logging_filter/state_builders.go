// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// filterSetsToList maps the filter sets a filter belongs to into a types.List.
func filterSetsToList(sets []jamfprotect.UnifiedLoggingFilterSetRef, diags *diag.Diagnostics) types.List {
	vals := make([]attr.Value, 0, len(sets))
	for _, s := range sets {
		vals = append(vals, types.ObjectValueMust(filterSetAttrTypes, map[string]attr.Value{
			"uuid": types.StringValue(s.UUID),
			"name": types.StringValue(s.Name),
		}))
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: filterSetAttrTypes}, vals)
	diags.Append(d...)
	return list
}

// apiToState maps the API response into the resource state.
func (r *UnifiedLoggingFilterResource) apiToState(_ context.Context, data *UnifiedLoggingFilterResourceModel, api jamfprotect.UnifiedLoggingFilter) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Filter = types.StringValue(api.Filter)
	data.Enabled = types.BoolValue(api.Enabled)
	data.Tags = common.StringsToSet(api.Tags)
	data.Created = types.StringValue(api.Created)
	data.Description = types.StringValue(api.Description)
}
