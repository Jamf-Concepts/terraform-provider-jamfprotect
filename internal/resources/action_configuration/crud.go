// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func (r *ActionConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := data.Timeouts.Create(ctx, constants.DefaultCreateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	input := r.buildInput(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	result, err := r.client.CreateActionConfig(ctx, *input)
	if err != nil {
		resp.Diagnostics.AddError("Error creating action config", err.Error())
		return
	}

	r.applyState(ctx, &data, result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing action configuration ID",
			"CreateActionConfig did not return an ID for the new action configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created action config", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ActionConfigResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing action configuration identity",
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

	readTimeout, diags := data.Timeouts.Read(ctx, constants.DefaultReadTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	result, err := r.client.GetActionConfig(ctx, data.ID.ValueString())
	if err != nil {
		if common.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading action config", err.Error())
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.applyState(ctx, &data, *result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing action configuration ID",
			"GetActionConfig did not return an ID for the action configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ActionConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	updateTimeout, diags := data.Timeouts.Update(ctx, constants.DefaultUpdateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	input := r.buildInput(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	result, err := r.client.UpdateActionConfig(ctx, data.ID.ValueString(), *input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating action config", err.Error())
		return
	}

	r.applyState(ctx, &data, result, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing action configuration ID",
			"UpdateActionConfig did not return an ID for the action configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := data.Timeouts.Delete(ctx, constants.DefaultDeleteTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if err := r.client.DeleteActionConfig(ctx, data.ID.ValueString()); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "action config already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting action config", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted action config", map[string]any{"id": data.ID.ValueString()})
}
