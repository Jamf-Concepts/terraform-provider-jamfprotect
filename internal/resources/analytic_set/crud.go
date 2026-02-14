package analytic_set

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
)

func (r *AnalyticSetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AnalyticSetResourceModel
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

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var result struct {
		CreateAnalyticSet analyticSetResourceAPIModel `json:"createAnalyticSet"`
	}
	if err := r.client.Query(ctx, createAnalyticSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating analytic set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateAnalyticSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created analytic set", map[string]any{"uuid": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticSetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AnalyticSetResourceModel
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

	vars := map[string]any{
		"uuid":             data.ID.ValueString(),
		"RBAC_Plan":        true,
		"excludeAnalytics": false,
	}
	var result struct {
		GetAnalyticSet *analyticSetResourceAPIModel `json:"getAnalyticSet"`
	}
	if err := r.client.Query(ctx, getAnalyticSetQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading analytic set", err.Error())
		return
	}
	if result.GetAnalyticSet == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetAnalyticSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticSetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AnalyticSetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UUID comes from state, not plan.
	var state AnalyticSetResourceModel
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

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	vars["uuid"] = data.ID.ValueString()

	var result struct {
		UpdateAnalyticSet analyticSetResourceAPIModel `json:"updateAnalyticSet"`
	}
	if err := r.client.Query(ctx, updateAnalyticSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating analytic set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateAnalyticSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticSetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AnalyticSetResourceModel
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

	vars := map[string]any{"uuid": data.ID.ValueString()}
	if err := r.client.Query(ctx, deleteAnalyticSetMutation, vars, nil); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "analytic set already deleted", map[string]any{"uuid": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting analytic set", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted analytic set", map[string]any{"uuid": data.ID.ValueString()})
}
