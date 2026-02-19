// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package change_management

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *ChangeManagementResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ChangeManagementResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutsValue := data.Timeouts
	if timeoutsValue.IsNull() || timeoutsValue.IsUnknown() {
		timeoutsValue = common.EmptyTimeoutsValue()
	}

	createTimeout, diags := timeoutsValue.Create(ctx, constants.DefaultCreateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	result, err := r.service.UpdateOrganizationConfigFreeze(ctx, data.EnableFreeze.ValueBool())
	if err != nil {
		if data.EnableFreeze.ValueBool() || !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error updating change management", err.Error())
			return
		}
		fallback, readErr := r.service.GetConfigFreeze(ctx)
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
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "updated change management", map[string]any{"id": data.ID.ValueString()})
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

	timeoutsValue := data.Timeouts
	if timeoutsValue.IsNull() || timeoutsValue.IsUnknown() {
		timeoutsValue = common.EmptyTimeoutsValue()
	}

	readTimeout, diags := timeoutsValue.Read(ctx, constants.DefaultReadTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	result, err := r.service.GetConfigFreeze(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading change management", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
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

	timeoutsValue := data.Timeouts
	if timeoutsValue.IsNull() || timeoutsValue.IsUnknown() {
		timeoutsValue = common.EmptyTimeoutsValue()
	}

	updateTimeout, diags := timeoutsValue.Update(ctx, constants.DefaultUpdateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	result, err := r.service.UpdateOrganizationConfigFreeze(ctx, data.EnableFreeze.ValueBool())
	if err != nil {
		if data.EnableFreeze.ValueBool() || !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error updating change management", err.Error())
			return
		}
		fallback, readErr := r.service.GetConfigFreeze(ctx)
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChangeManagementResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ChangeManagementResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutsValue := data.Timeouts
	if timeoutsValue.IsNull() || timeoutsValue.IsUnknown() {
		timeoutsValue = common.EmptyTimeoutsValue()
	}

	deleteTimeout, diags := timeoutsValue.Delete(ctx, constants.DefaultDeleteTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if _, err := r.service.UpdateOrganizationConfigFreeze(ctx, false); err != nil {
		if !isChangeFreezeNotActiveError(err) {
			resp.Diagnostics.AddError("Error deleting change management", err.Error())
			return
		}
	}

	tflog.Trace(ctx, "reset change management", map[string]any{"id": data.ID.ValueString()})
}
