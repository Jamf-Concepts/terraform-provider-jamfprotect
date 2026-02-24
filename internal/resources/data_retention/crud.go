// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_retention

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *DataRetentionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DataRetentionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutsValue := common.ResolveTimeouts(data.Timeouts)

	createTimeout, diags := timeoutsValue.Create(ctx, constants.DefaultCreateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	input := buildDataRetentionInput(data)
	result, err := r.service.UpdateDataRetention(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating data retention", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "updated data retention", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DataRetentionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DataRetentionResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing data retention identity",
				"The resource has no prior state and no identity data to refresh from.",
			)
			return
		}
		resp.Diagnostics.Append(req.Identity.GetAttribute(ctx, path.Root("id"), &data.ID)...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Timeouts = common.EmptyTimeoutsValue()
	} else {
		resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	timeoutsValue := common.ResolveTimeouts(data.Timeouts)

	readTimeout, diags := timeoutsValue.Read(ctx, constants.DefaultReadTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	result, err := r.service.GetDataRetention(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading data retention", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DataRetentionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DataRetentionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state DataRetentionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	timeoutsValue := common.ResolveTimeouts(data.Timeouts)

	updateTimeout, diags := timeoutsValue.Update(ctx, constants.DefaultUpdateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	input := buildDataRetentionInput(data)
	result, err := r.service.UpdateDataRetention(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating data retention", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DataRetentionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DataRetentionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "retained data retention settings", map[string]any{"id": data.ID.ValueString()})
}
