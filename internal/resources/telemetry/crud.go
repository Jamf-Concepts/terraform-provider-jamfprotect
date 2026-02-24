// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Create creates a telemetry v2 configuration.
func (r *TelemetryV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TelemetryV2ResourceModel
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

	input := r.buildInput(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	result, err := r.service.CreateTelemetryV2(ctx, *input)
	if err != nil {
		resp.Diagnostics.AddError("Error creating telemetry v2 configuration", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing telemetry v2 ID",
			"CreateTelemetryV2 did not return an ID for the telemetry v2 configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), data.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created telemetry v2 configuration", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read refreshes telemetry v2 state from the API.
func (r *TelemetryV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TelemetryV2ResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing telemetry v2 identity",
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

	result, err := r.service.GetTelemetryV2(ctx, data.ID.ValueString())
	if err != nil {
		if common.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading telemetry v2 configuration", err.Error())
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing telemetry v2 ID",
			"GetTelemetryV2 did not return an ID for the telemetry v2 configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), data.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates a telemetry v2 configuration.
func (r *TelemetryV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TelemetryV2ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state TelemetryV2ResourceModel
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

	input := r.buildInput(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	result, err := r.service.UpdateTelemetryV2(ctx, data.ID.ValueString(), *input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating telemetry v2 configuration", err.Error())
		return
	}

	r.apiToState(ctx, &data, result)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing telemetry v2 ID",
			"UpdateTelemetryV2 did not return an ID for the telemetry v2 configuration.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), data.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete removes a telemetry v2 configuration.
func (r *TelemetryV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TelemetryV2ResourceModel
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

	if err := r.service.DeleteTelemetryV2(ctx, data.ID.ValueString()); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "telemetry v2 configuration already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting telemetry v2 configuration", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted telemetry v2 configuration", map[string]any{"id": data.ID.ValueString()})
}
