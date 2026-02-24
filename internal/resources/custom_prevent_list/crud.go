package custom_prevent_list

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/common/constants"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *CustomPreventListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CustomPreventListResourceModel
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

	created, err := r.service.CreateCustomPreventList(ctx, *input)
	if err != nil {
		resp.Diagnostics.AddError("Error creating custom prevent list", err.Error())
		return
	}

	r.applyState(ctx, &data, created, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing prevent list ID",
			"CreateCustomPreventList did not return an ID for the new prevent list.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created custom prevent list", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CustomPreventListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CustomPreventListResourceModel
	if req.State.Raw.IsNull() {
		if req.Identity == nil {
			resp.Diagnostics.AddError(
				"Missing prevent list identity",
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

	customPreventList, err := r.service.GetCustomPreventList(ctx, data.ID.ValueString())
	if err != nil {
		if common.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading custom prevent list", err.Error())
		return
	}
	if customPreventList == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.applyState(ctx, &data, *customPreventList, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing prevent list ID",
			"GetCustomPreventList did not return an ID for the prevent list.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CustomPreventListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data CustomPreventListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutsValue := common.ResolveTimeouts(data.Timeouts)

	var state CustomPreventListResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

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
	updated, err := r.service.UpdateCustomPreventList(ctx, data.ID.ValueString(), *input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating custom prevent list", err.Error())
		return
	}

	r.applyState(ctx, &data, updated, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Timeouts = timeoutsValue
	if data.ID.IsNull() || data.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing prevent list ID",
			"UpdateCustomPreventList did not return an ID for the prevent list.",
		)
		return
	}
	resp.Diagnostics.Append(resp.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(data.ID.ValueString()))...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CustomPreventListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CustomPreventListResourceModel
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

	if err := r.service.DeleteCustomPreventList(ctx, data.ID.ValueString()); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "custom prevent list already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting custom prevent list", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted custom prevent list", map[string]any{"id": data.ID.ValueString()})
}
