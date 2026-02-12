// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &ActionConfigResource{}
var _ resource.ResourceWithImportState = &ActionConfigResource{}

func NewActionConfigResource() resource.Resource {
	return &ActionConfigResource{}
}

// ActionConfigResource manages a Jamf Protect action configuration.
type ActionConfigResource struct {
	client *graphql.Client
}

func (r *ActionConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_action_config"
}

func (r *ActionConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an action configuration in Jamf Protect. Action configurations define the alert data enrichment settings and reporting clients for a plan.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the action configuration.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hash": schema.StringAttribute{
				MarkdownDescription: "The configuration hash.",
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the action configuration.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the action configuration.",
				Optional:            true,
				Computed:            true,
			},
			"alert_config": schema.StringAttribute{
				MarkdownDescription: "The alert configuration as a JSON-encoded string. Defines which data attributes and related objects to include in alerts for each event type.",
				Required:            true,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
		},
	}
}

func (r *ActionConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ActionConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars, err := r.buildVariables(data)
	if err != nil {
		resp.Diagnostics.AddError("Error building variables", err.Error())
		return
	}

	var result struct {
		CreateActionConfigs actionConfigAPIModel `json:"createActionConfigs"`
	}
	if err := r.client.Query(ctx, createActionConfigMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating action config", err.Error())
		return
	}

	r.apiToState(&data, result.CreateActionConfigs)
	tflog.Trace(ctx, "created action config", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"id": data.ID.ValueString()}
	var result struct {
		GetActionConfigs *actionConfigAPIModel `json:"getActionConfigs"`
	}
	if err := r.client.Query(ctx, getActionConfigQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading action config", err.Error())
		return
	}
	if result.GetActionConfigs == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(&data, *result.GetActionConfigs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ActionConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	vars, err := r.buildVariables(data)
	if err != nil {
		resp.Diagnostics.AddError("Error building variables", err.Error())
		return
	}
	vars["id"] = data.ID.ValueString()

	var result struct {
		UpdateActionConfigs actionConfigAPIModel `json:"updateActionConfigs"`
	}
	if err := r.client.Query(ctx, updateActionConfigMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating action config", err.Error())
		return
	}

	r.apiToState(&data, result.UpdateActionConfigs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"id": data.ID.ValueString()}
	if err := r.client.Query(ctx, deleteActionConfigMutation, vars, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting action config", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted action config", map[string]any{"id": data.ID.ValueString()})
}

func (r *ActionConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data ActionConfigResourceModel
	data.ID = types.StringValue(req.ID)

	vars := map[string]any{"id": req.ID}
	var result struct {
		GetActionConfigs *actionConfigAPIModel `json:"getActionConfigs"`
	}
	if err := r.client.Query(ctx, getActionConfigQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error importing action config", err.Error())
		return
	}
	if result.GetActionConfigs == nil {
		resp.Diagnostics.AddError("Action config not found", fmt.Sprintf("No action config with ID %q", req.ID))
		return
	}

	r.apiToState(&data, *result.GetActionConfigs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
