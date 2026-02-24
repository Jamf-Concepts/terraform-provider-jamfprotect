package data_forwarding

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *DataForwardingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DataForwardingResourceModel
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

	current, err := r.service.GetDataForwarding(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading data forwarding", err.Error())
		return
	}

	input := buildDataForwardingInput(ctx, data, current.Forward.Sentinel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.service.UpdateDataForwarding(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating data forwarding", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.Forward, result.UUID, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "updated data forwarding", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DataForwardingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DataForwardingResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing data forwarding identity",
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

	result, err := r.service.GetDataForwarding(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading data forwarding", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.Forward, result.UUID, &resp.Diagnostics)
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

func (r *DataForwardingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DataForwardingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state DataForwardingResourceModel
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

	current, err := r.service.GetDataForwarding(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading data forwarding", err.Error())
		return
	}

	input := buildDataForwardingInput(ctx, data, current.Forward.Sentinel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.service.UpdateDataForwarding(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating data forwarding", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.Forward, result.UUID, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DataForwardingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DataForwardingResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "retained data forwarding settings", map[string]any{"id": data.ID.ValueString()})
}
