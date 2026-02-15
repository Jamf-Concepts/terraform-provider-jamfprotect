// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

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

func (r *PreventListResource) buildVariables(ctx context.Context, data PreventListResourceModel, diags *diag.Diagnostics) *jamfprotect.CustomPreventListInput {
	input := &jamfprotect.CustomPreventListInput{
		Name: data.Name.ValueString(),
		Type: data.Type.ValueString(),
	}
	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}
	input.Tags = common.ListToStrings(ctx, data.Tags, diags)
	input.List = common.ListToStrings(ctx, data.List, diags)
	return input
}

func (r *PreventListResource) apiToState(_ context.Context, data *PreventListResourceModel, api jamfprotect.CustomPreventList, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Type = types.StringValue(api.Type)
	data.EntryCount = types.Int64Value(api.Count)
	data.Created = types.StringValue(api.Created)
	data.List = common.StringsToList(api.List)
	data.Tags = common.StringsToList(api.Tags)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
