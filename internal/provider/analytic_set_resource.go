// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &AnalyticSetResource{}
var _ resource.ResourceWithImportState = &AnalyticSetResource{}

func NewAnalyticSetResource() resource.Resource {
	return &AnalyticSetResource{}
}

// AnalyticSetResource manages a Jamf Protect analytic set.
type AnalyticSetResource struct {
	client *graphql.Client
}

func (r *AnalyticSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytic_set"
}

func (r *AnalyticSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an analytic set in Jamf Protect. Analytic sets are collections of analytics that can be associated with plans.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the analytic set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the analytic set.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the analytic set.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"types": schema.ListAttribute{
				MarkdownDescription: "The types of analytics in this set. Valid values are `Report` and `Prevent`.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"analytics": schema.ListAttribute{
				MarkdownDescription: "A list of analytic UUIDs to include in this set.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
			"managed": schema.BoolAttribute{
				MarkdownDescription: "Whether this is a Jamf-managed analytic set.",
				Computed:            true,
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *AnalyticSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*graphql.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *graphql.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

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
		if isNotFoundError(err) {
			tflog.Trace(ctx, "analytic set already deleted", map[string]any{"uuid": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting analytic set", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted analytic set", map[string]any{"uuid": data.ID.ValueString()})
}

func (r *AnalyticSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
