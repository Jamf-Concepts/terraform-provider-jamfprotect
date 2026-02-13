// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ resource.Resource = &UnifiedLoggingFilterResource{}
var _ resource.ResourceWithImportState = &UnifiedLoggingFilterResource{}

func NewUnifiedLoggingFilterResource() resource.Resource {
	return &UnifiedLoggingFilterResource{}
}

// UnifiedLoggingFilterResource manages a Jamf Protect unified logging filter.
type UnifiedLoggingFilterResource struct {
	client *client.Client
}

func (r *UnifiedLoggingFilterResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter"
}

func (r *UnifiedLoggingFilterResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a unified logging filter in Jamf Protect. Unified logging filters capture macOS unified log entries that match a given predicate.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the unified logging filter.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the unified logging filter.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the unified logging filter.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"filter": schema.StringAttribute{
				MarkdownDescription: "The predicate filter expression (NSPredicate format).",
				Required:            true,
			},
			"level": schema.StringAttribute{
				MarkdownDescription: "The unified logging level.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("DEFAULT"),
				},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the filter is enabled. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: "A list of tags for the unified logging filter.",
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
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *UnifiedLoggingFilterResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *UnifiedLoggingFilterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data UnifiedLoggingFilterResourceModel
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
		CreateUnifiedLoggingFilter unifiedLoggingFilterAPIModel `json:"createUnifiedLoggingFilter"`
	}
	if err := r.client.Query(ctx, createUnifiedLoggingFilterMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating unified logging filter", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateUnifiedLoggingFilter, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created unified logging filter", map[string]any{"uuid": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UnifiedLoggingFilterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data UnifiedLoggingFilterResourceModel
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

	vars := map[string]any{"uuid": data.ID.ValueString()}
	var result struct {
		GetUnifiedLoggingFilter *unifiedLoggingFilterAPIModel `json:"getUnifiedLoggingFilter"`
	}
	if err := r.client.Query(ctx, getUnifiedLoggingFilterQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading unified logging filter", err.Error())
		return
	}
	if result.GetUnifiedLoggingFilter == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetUnifiedLoggingFilter, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UnifiedLoggingFilterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data UnifiedLoggingFilterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state UnifiedLoggingFilterResourceModel
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
		UpdateUnifiedLoggingFilter unifiedLoggingFilterAPIModel `json:"updateUnifiedLoggingFilter"`
	}
	if err := r.client.Query(ctx, updateUnifiedLoggingFilterMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating unified logging filter", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateUnifiedLoggingFilter, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UnifiedLoggingFilterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data UnifiedLoggingFilterResourceModel
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
	if err := r.client.Query(ctx, deleteUnifiedLoggingFilterMutation, vars, nil); err != nil {
		if isNotFoundError(err) {
			tflog.Trace(ctx, "unified logging filter already deleted", map[string]any{"uuid": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting unified logging filter", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted unified logging filter", map[string]any{"uuid": data.ID.ValueString()})
}

func (r *UnifiedLoggingFilterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
