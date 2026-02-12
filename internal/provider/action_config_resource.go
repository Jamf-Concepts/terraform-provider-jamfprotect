// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
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

// ActionConfigResourceModel maps the resource schema data.
type ActionConfigResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Hash        types.String `tfsdk:"hash"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	AlertConfig types.String `tfsdk:"alert_config"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
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
// GraphQL queries — stripped of @skip/@include RBAC directives.
// The alertConfig response is complex with many nested types; we request it
// in full and expose it as a JSON string for maximum flexibility.
// ---------------------------------------------------------------------------

const actionConfigFields = `
fragment ActionConfigsFields on ActionConfigs {
  id
  name
  description
  hash
  created
  updated
  alertConfig {
    data {
      binary { attrs related }
      clickEvent { attrs related }
      downloadEvent { attrs related }
      file { attrs related }
      fsEvent { attrs related }
      group { attrs related }
      procEvent { attrs related }
      process { attrs related }
      screenshotEvent { attrs related }
      usbEvent { attrs related }
      user { attrs related }
      gkEvent { attrs related }
      keylogRegisterEvent { attrs related }
      mrtEvent { attrs related }
    }
  }
}
`

const createActionConfigMutation = `
mutation createActionConfigs(
  $name: String!,
  $description: String!,
  $alertConfig: ActionConfigsAlertConfigInput!
) {
  createActionConfigs(input: {
    name: $name,
    description: $description,
    alertConfig: $alertConfig
  }) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const getActionConfigQuery = `
query getActionConfigs($id: ID!) {
  getActionConfigs(id: $id) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const updateActionConfigMutation = `
mutation updateActionConfigs(
  $id: ID!,
  $name: String!,
  $description: String!,
  $alertConfig: ActionConfigsAlertConfigInput!
) {
  updateActionConfigs(id: $id, input: {
    name: $name,
    description: $description,
    alertConfig: $alertConfig
  }) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const deleteActionConfigMutation = `
mutation deleteActionConfigs($id: ID!) {
  deleteActionConfigs(id: $id) {
    id
  }
}
`

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

// ---------------------------------------------------------------------------
// API model
// ---------------------------------------------------------------------------

type actionConfigAPIModel struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Hash        string          `json:"hash"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
	AlertConfig json.RawMessage `json:"alertConfig"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *ActionConfigResource) buildVariables(data ActionConfigResourceModel) (map[string]any, error) {
	vars := map[string]any{
		"name": data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Parse the alert_config JSON string into a map for the GraphQL variables.
	var alertConfig any
	if err := json.Unmarshal([]byte(data.AlertConfig.ValueString()), &alertConfig); err != nil {
		return nil, fmt.Errorf("alert_config must be valid JSON: %w", err)
	}
	vars["alertConfig"] = alertConfig

	return vars, nil
}

func (r *ActionConfigResource) apiToState(data *ActionConfigResourceModel, api actionConfigAPIModel) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	// Store the alert config as a JSON string.
	if api.AlertConfig != nil {
		data.AlertConfig = types.StringValue(string(api.AlertConfig))
	}
}
