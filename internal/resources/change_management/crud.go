// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package change_management

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *ChangeManagementResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ChangeManagementResourceModel
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

	result, err := r.client.UpdateOrganizationConfigFreeze(ctx, data.EnableFreeze.ValueBool())
	if err != nil {
		if data.EnableFreeze.ValueBool() || !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error updating change management", err.Error())
			return
		}
		fallback, readErr := r.client.GetConfigFreeze(ctx)
		if readErr != nil {
			resp.Diagnostics.AddError("Error reading change management", readErr.Error())
			return
		}
		result = fallback
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing change management ID",
			"UpdateOrganizationConfigFreeze did not return an ID for the change management resource.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChangeManagementResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ChangeManagementResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing change management identity",
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

	result, err := r.client.GetConfigFreeze(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading change management", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing change management ID",
			"GetConfigFreeze did not return an ID for the change management resource.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChangeManagementResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ChangeManagementResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ChangeManagementResourceModel
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

	result, err := r.client.UpdateOrganizationConfigFreeze(ctx, data.EnableFreeze.ValueBool())
	if err != nil {
		if data.EnableFreeze.ValueBool() || !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error updating change management", err.Error())
			return
		}
		fallback, readErr := r.client.GetConfigFreeze(ctx)
		if readErr != nil {
			resp.Diagnostics.AddError("Error reading change management", readErr.Error())
			return
		}
		result = fallback
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing change management ID",
			"UpdateOrganizationConfigFreeze did not return an ID for the change management resource.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChangeManagementResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ChangeManagementResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutsValue := common.ResolveTimeouts(data.Timeouts)

	deleteTimeout, diags := timeoutsValue.Delete(ctx, constants.DefaultDeleteTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if _, err := r.client.UpdateOrganizationConfigFreeze(ctx, false); err != nil {
		if !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error deleting change management", err.Error())
			return
		}
	}

	tflog.Trace(ctx, "reset change management", map[string]any{"id": data.ID.ValueString()})
}
