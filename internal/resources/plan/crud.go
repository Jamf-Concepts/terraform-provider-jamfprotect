package plan

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *PlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := data.Timeouts.Create(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	input := r.buildVariables(ctx, data, commsFQDNPlaceholder, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	created, err := r.service.CreatePlan(ctx, *input)
	if err != nil {
		resp.Diagnostics.AddError("Error creating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, created, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created plan", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := data.Timeouts.Read(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	plan, err := r.service.GetPlan(ctx, data.ID.ValueString())
	if err != nil {
		if common.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading plan", err.Error())
		return
	}
	if plan == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	updateTimeout, diags := data.Timeouts.Update(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	current, err := r.service.GetPlan(ctx, data.ID.ValueString())
	if err != nil {
		if common.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading plan for update", err.Error())
		return
	}
	if current == nil || current.CommsConfig == nil || current.CommsConfig.FQDN == "" {
		resp.Diagnostics.AddError("Missing communications configuration", "Expected commsConfig.fqdn to be set for update.")
		return
	}

	input := r.buildVariables(ctx, data, current.CommsConfig.FQDN, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if input == nil {
		return
	}

	updated, err := r.service.UpdatePlan(ctx, data.ID.ValueString(), *input)
	if err != nil {
		resp.Diagnostics.AddError("Error updating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, updated, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := data.Timeouts.Delete(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if err := r.service.DeletePlan(ctx, data.ID.ValueString()); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "plan already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting plan", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted plan", map[string]any{"id": data.ID.ValueString()})
}
