// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
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

// PreventListResourceModel maps the resource schema data.
type PreventListResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	Tags        types.List   `tfsdk:"tags"`
	List        types.List   `tfsdk:"list"`
	Count       types.Int64  `tfsdk:"count"`
	Created     types.String `tfsdk:"created"`
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
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "The type of prevent list. Valid values: `TEAMID`, `FILEHASH`, `CDHASH`, `SIGNINGID`.",
				Required:            true,
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
			"count": schema.Int64Attribute{
				MarkdownDescription: "The number of entries in the prevent list.",
				Computed:            true,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
			},
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
// GraphQL queries
// ---------------------------------------------------------------------------

const preventListFields = `
fragment PreventListFields on PreventList {
  id
  name
  type
  count
  list
  created
  description
}
`

const createPreventListMutation = `
mutation createPreventList(
  $name: String!,
  $tags: [String]!,
  $type: PREVENT_LIST_TYPE!,
  $list: [String]!,
  $description: String
) {
  createPreventList(input: {
    name: $name,
    tags: $tags,
    type: $type,
    list: $list,
    description: $description
  }) {
    ...PreventListFields
  }
}
` + preventListFields

const getPreventListQuery = `
query getPreventList($id: ID!) {
  getPreventList(id: $id) {
    ...PreventListFields
  }
}
` + preventListFields

const updatePreventListMutation = `
mutation updatePreventList(
  $id: ID!,
  $name: String!,
  $tags: [String]!,
  $type: PREVENT_LIST_TYPE!,
  $list: [String]!,
  $description: String
) {
  updatePreventList(id: $id, input: {
    name: $name,
    tags: $tags,
    type: $type,
    list: $list,
    description: $description
  }) {
    ...PreventListFields
  }
}
` + preventListFields

const deletePreventListMutation = `
mutation deletePreventList($id: ID!) {
  deletePreventList(id: $id) {
    id
  }
}
`

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *PreventListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PreventListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	r.apiToState(&data, result.CreatePreventList)
	tflog.Trace(ctx, "created prevent list", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PreventListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PreventListResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	r.apiToState(&data, *result.GetPreventList)
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

	r.apiToState(&data, result.UpdatePreventList)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PreventListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PreventListResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"id": data.ID.ValueString()}
	if err := r.client.Query(ctx, deletePreventListMutation, vars, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting prevent list", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted prevent list", map[string]any{"id": data.ID.ValueString()})
}

func (r *PreventListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data PreventListResourceModel
	data.ID = types.StringValue(req.ID)

	vars := map[string]any{"id": req.ID}
	var result struct {
		GetPreventList *preventListAPIModel `json:"getPreventList"`
	}
	if err := r.client.Query(ctx, getPreventListQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error importing prevent list", err.Error())
		return
	}
	if result.GetPreventList == nil {
		resp.Diagnostics.AddError("Prevent list not found", fmt.Sprintf("No prevent list with ID %q", req.ID))
		return
	}

	r.apiToState(&data, *result.GetPreventList)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// ---------------------------------------------------------------------------
// API model
// ---------------------------------------------------------------------------

type preventListAPIModel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Count       int64    `json:"count"`
	List        []string `json:"list"`
	Created     string   `json:"created"`
	Description string   `json:"description"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *PreventListResource) buildVariables(ctx context.Context, data PreventListResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name": data.Name.ValueString(),
		"type": data.Type.ValueString(),
	}
	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	}
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	vars["list"] = listToStrings(ctx, data.List, diags)
	return vars
}

func (r *PreventListResource) apiToState(data *PreventListResourceModel, api preventListAPIModel) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Type = types.StringValue(api.Type)
	data.Count = types.Int64Value(api.Count)
	data.Created = types.StringValue(api.Created)
	data.List = stringsToList(api.List)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
