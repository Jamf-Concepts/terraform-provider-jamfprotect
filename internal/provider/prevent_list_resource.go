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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &PreventListResource{}
var _ resource.ResourceWithImportState = &PreventListResource{}

func NewPreventListResource() resource.Resource {
	return &PreventListResource{}
}

// PreventListResource manages a Jamf Protect prevent list (threat prevention allow/block list).
type PreventListResource struct {
	client *graphql.Client
}

func (r *PreventListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prevent_list"
}

func (r *PreventListResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a prevent list in Jamf Protect. Prevent lists allow you to define allow/block entries by Team ID, file hash, CDHash, or signing ID for threat prevention.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the prevent list.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the prevent list.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the prevent list.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "The type of prevent list.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("TEAMID", "FILEHASH", "CDHASH", "SIGNINGID"),
				},
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: "A list of tags for the prevent list.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"list": schema.ListAttribute{
				MarkdownDescription: "The list of entries (identifiers) in the prevent list.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"entry_count": schema.Int64Attribute{
				MarkdownDescription: "The number of entries in the prevent list.",
				Computed:            true,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
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

func (r *PreventListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PreventListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PreventListResourceModel
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
		CreatePreventList preventListAPIModel `json:"createPreventList"`
	}
	if err := r.client.Query(ctx, createPreventListMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating prevent list", err.Error())
		return
	}

	planTags := data.Tags
	r.apiToState(ctx, &data, result.CreatePreventList, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Tags = planTags
	tflog.Trace(ctx, "created prevent list", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PreventListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PreventListResourceModel
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

	vars := map[string]any{"id": data.ID.ValueString()}
	var result struct {
		GetPreventList *preventListAPIModel `json:"getPreventList"`
	}
	if err := r.client.Query(ctx, getPreventListQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading prevent list", err.Error())
		return
	}
	if result.GetPreventList == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	stateTags := data.Tags
	r.apiToState(ctx, &data, *result.GetPreventList, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Tags = stateTags
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PreventListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PreventListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state PreventListResourceModel
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
	vars["id"] = data.ID.ValueString()

	var result struct {
		UpdatePreventList preventListAPIModel `json:"updatePreventList"`
	}
	if err := r.client.Query(ctx, updatePreventListMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating prevent list", err.Error())
		return
	}

	planTags := data.Tags
	r.apiToState(ctx, &data, result.UpdatePreventList, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Tags = planTags
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PreventListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PreventListResourceModel
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

	vars := map[string]any{"id": data.ID.ValueString()}
	if err := r.client.Query(ctx, deletePreventListMutation, vars, nil); err != nil {
		if isNotFoundError(err) {
			tflog.Trace(ctx, "prevent list already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting prevent list", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted prevent list", map[string]any{"id": data.ID.ValueString()})
}

func (r *PreventListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
