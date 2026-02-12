// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &UnifiedLoggingFilterResource{}
var _ resource.ResourceWithImportState = &UnifiedLoggingFilterResource{}

func NewUnifiedLoggingFilterResource() resource.Resource {
	return &UnifiedLoggingFilterResource{}
}

// UnifiedLoggingFilterResource manages a Jamf Protect unified logging filter.
type UnifiedLoggingFilterResource struct {
	client *graphql.Client
}

// UnifiedLoggingFilterResourceModel maps the resource schema data.
type UnifiedLoggingFilterResourceModel struct {
	UUID        types.String `tfsdk:"uuid"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Filter      types.String `tfsdk:"filter"`
	Level       types.String `tfsdk:"level"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Tags        types.List   `tfsdk:"tags"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
}

func (r *UnifiedLoggingFilterResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter"
}

func (r *UnifiedLoggingFilterResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a unified logging filter in Jamf Protect. Unified logging filters capture macOS unified log entries that match a given predicate.",
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
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
			},
			"filter": schema.StringAttribute{
				MarkdownDescription: "The predicate filter expression (NSPredicate format).",
				Required:            true,
			},
			"level": schema.StringAttribute{
				MarkdownDescription: "The unified logging level. The only known valid value is `DEFAULT`.",
				Required:            true,
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
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
		},
	}
}

func (r *UnifiedLoggingFilterResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

const unifiedLoggingFilterFields = `
fragment UnifiedLoggingFilterFields on UnifiedLoggingFilter {
  uuid
  name
  description
  created
  updated
  filter
  tags
  enabled
  level
}
`

const createUnifiedLoggingFilterMutation = `
mutation createUnifiedLoggingFilter(
  $name: String!,
  $description: String,
  $tags: [String]!,
  $filter: String!,
  $enabled: Boolean,
  $level: UNIFIED_LOGGING_LEVEL!
) {
  createUnifiedLoggingFilter(input: {
    name: $name,
    description: $description,
    tags: $tags,
    filter: $filter,
    enabled: $enabled,
    level: $level
  }) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const getUnifiedLoggingFilterQuery = `
query getUnifiedLoggingFilter($uuid: ID!) {
  getUnifiedLoggingFilter(uuid: $uuid) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const updateUnifiedLoggingFilterMutation = `
mutation updateUnifiedLoggingFilter(
  $uuid: ID!,
  $name: String!,
  $description: String,
  $filter: String!,
  $tags: [String]!,
  $enabled: Boolean,
  $level: UNIFIED_LOGGING_LEVEL!
) {
  updateUnifiedLoggingFilter(uuid: $uuid, input: {
    name: $name,
    description: $description,
    filter: $filter,
    tags: $tags,
    enabled: $enabled,
    level: $level
  }) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const deleteUnifiedLoggingFilterMutation = `
mutation deleteUnifiedLoggingFilter($uuid: ID!) {
  deleteUnifiedLoggingFilter(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *UnifiedLoggingFilterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data UnifiedLoggingFilterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	r.apiToState(&data, result.CreateUnifiedLoggingFilter)
	tflog.Trace(ctx, "created unified logging filter", map[string]any{"uuid": data.UUID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UnifiedLoggingFilterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data UnifiedLoggingFilterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"uuid": data.UUID.ValueString()}
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

	r.apiToState(&data, *result.GetUnifiedLoggingFilter)
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
	data.UUID = state.UUID

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	vars["uuid"] = data.UUID.ValueString()

	var result struct {
		UpdateUnifiedLoggingFilter unifiedLoggingFilterAPIModel `json:"updateUnifiedLoggingFilter"`
	}
	if err := r.client.Query(ctx, updateUnifiedLoggingFilterMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating unified logging filter", err.Error())
		return
	}

	r.apiToState(&data, result.UpdateUnifiedLoggingFilter)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UnifiedLoggingFilterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data UnifiedLoggingFilterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"uuid": data.UUID.ValueString()}
	if err := r.client.Query(ctx, deleteUnifiedLoggingFilterMutation, vars, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting unified logging filter", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted unified logging filter", map[string]any{"uuid": data.UUID.ValueString()})
}

func (r *UnifiedLoggingFilterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data UnifiedLoggingFilterResourceModel
	data.UUID = types.StringValue(req.ID)

	vars := map[string]any{"uuid": req.ID}
	var result struct {
		GetUnifiedLoggingFilter *unifiedLoggingFilterAPIModel `json:"getUnifiedLoggingFilter"`
	}
	if err := r.client.Query(ctx, getUnifiedLoggingFilterQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error importing unified logging filter", err.Error())
		return
	}
	if result.GetUnifiedLoggingFilter == nil {
		resp.Diagnostics.AddError("Unified logging filter not found", fmt.Sprintf("No unified logging filter with UUID %q", req.ID))
		return
	}

	r.apiToState(&data, *result.GetUnifiedLoggingFilter)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// ---------------------------------------------------------------------------
// API model
// ---------------------------------------------------------------------------

type unifiedLoggingFilterAPIModel struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Filter      string   `json:"filter"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	Level       string   `json:"level"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *UnifiedLoggingFilterResource) buildVariables(ctx context.Context, data UnifiedLoggingFilterResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":    data.Name.ValueString(),
		"filter":  data.Filter.ValueString(),
		"level":   data.Level.ValueString(),
		"enabled": data.Enabled.ValueBool(),
	}
	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	}
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	return vars
}

func (r *UnifiedLoggingFilterResource) apiToState(data *UnifiedLoggingFilterResourceModel, api unifiedLoggingFilterAPIModel) {
	data.UUID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Filter = types.StringValue(api.Filter)
	data.Level = types.StringValue(api.Level)
	data.Enabled = types.BoolValue(api.Enabled)
	data.Tags = stringsToList(api.Tags)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
