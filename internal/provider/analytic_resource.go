// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &AnalyticResource{}
var _ resource.ResourceWithImportState = &AnalyticResource{}

func NewAnalyticResource() resource.Resource {
	return &AnalyticResource{}
}

// AnalyticResource manages a Jamf Protect custom analytic.
type AnalyticResource struct {
	client *graphql.Client
}

// AnalyticResourceModel maps the resource schema data.
type AnalyticResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	InputType       types.String `tfsdk:"input_type"`
	Description     types.String `tfsdk:"description"`
	Filter          types.String `tfsdk:"filter"`
	Level           types.Int64  `tfsdk:"level"`
	Severity        types.String `tfsdk:"severity"`
	Tags            types.List   `tfsdk:"tags"`
	Categories      types.List   `tfsdk:"categories"`
	SnapshotFiles   types.List   `tfsdk:"snapshot_files"`
	Actions         types.List   `tfsdk:"actions"`
	AnalyticActions types.List   `tfsdk:"analytic_actions"`
	Context         types.List   `tfsdk:"context"`
	Created         types.String `tfsdk:"created"`
	Updated         types.String `tfsdk:"updated"`
}

// analyticActionModel maps AnalyticActionsInput / response.
type analyticActionModel struct {
	Name       types.String `tfsdk:"name"`
	Parameters types.Map    `tfsdk:"parameters"`
}

// analyticContextModel maps AnalyticContextInput / response.
type analyticContextModel struct {
	Name  types.String `tfsdk:"name"`
	Type  types.String `tfsdk:"type"`
	Exprs types.List   `tfsdk:"exprs"`
}

func (r *AnalyticResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytic"
}

func (r *AnalyticResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a custom analytic in Jamf Protect. Analytics define detection rules that monitor endpoint activity.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the analytic.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the analytic.",
				Required:            true,
			},
			"input_type": schema.StringAttribute{
				MarkdownDescription: "The input type for the analytic. Determines which endpoint event stream the analytic monitors.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"GPFSEvent",
						"GPDownloadEvent",
						"GPProcessEvent",
						"GPScreenshotEvent",
						"GPKeylogRegisterEvent",
						"GPClickEvent",
						"GPMRTEvent",
						"GPUSBEvent",
						"GPGatekeeperEvent",
					),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the analytic.",
				Optional:            true,
				Computed:            true,
			},
			"filter": schema.StringAttribute{
				MarkdownDescription: "The predicate filter expression for the analytic.",
				Required:            true,
			},
			"level": schema.Int64Attribute{
				MarkdownDescription: "The log level (integer) for the analytic.",
				Required:            true,
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "The severity of the analytic.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("High", "Medium", "Low", "Informational"),
				},
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: "A list of tags for the analytic.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"categories": schema.ListAttribute{
				MarkdownDescription: "A list of categories for the analytic.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"snapshot_files": schema.ListAttribute{
				MarkdownDescription: "A list of snapshot file paths to collect when the analytic triggers.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"actions": schema.ListAttribute{
				MarkdownDescription: "A list of legacy action names.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"analytic_actions": schema.ListNestedAttribute{
				MarkdownDescription: "Structured actions to perform when the analytic triggers.",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "The action name (e.g. `Log`, `SmartGroup`, `Webhook`).",
							Required:            true,
						},
						"parameters": schema.MapAttribute{
							MarkdownDescription: "Action parameters as key-value pairs (e.g. `{id = \"smartgroup\"}`).",
							Optional:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"context": schema.ListNestedAttribute{
				MarkdownDescription: "Context enrichment definitions for the analytic.",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "The context variable name.",
							Required:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The context variable type.",
							Required:            true,
						},
						"exprs": schema.ListAttribute{
							MarkdownDescription: "Expressions to evaluate for this context variable.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
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

func (r *AnalyticResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
// GraphQL queries – stripped of the @skip/@include directives the browser uses
// ---------------------------------------------------------------------------

const analyticFields = `
fragment AnalyticFields on Analytic {
  uuid
  name
  inputType
  filter
  description
  created
  updated
  actions
  analyticActions {
    name
    parameters
  }
  tags
  level
  severity
  snapshotFiles
  context {
    name
    type
    exprs
  }
  categories
}
`

const createAnalyticMutation = `
mutation createAnalytic(
  $name: String!,
  $inputType: String!,
  $description: String!,
  $actions: [String],
  $analyticActions: [AnalyticActionsInput]!,
  $tags: [String]!,
  $categories: [String]!,
  $filter: String!,
  $context: [AnalyticContextInput]!,
  $level: Int!,
  $severity: SEVERITY!,
  $snapshotFiles: [String]!
) {
  createAnalytic(input: {
    name: $name,
    inputType: $inputType,
    description: $description,
    actions: $actions,
    analyticActions: $analyticActions,
    tags: $tags,
    categories: $categories,
    filter: $filter,
    context: $context,
    level: $level,
    severity: $severity,
    snapshotFiles: $snapshotFiles
  }) {
    ...AnalyticFields
  }
}
` + analyticFields

const getAnalyticQuery = `
query getAnalytic($uuid: ID!) {
  getAnalytic(uuid: $uuid) {
    ...AnalyticFields
  }
}
` + analyticFields

const updateAnalyticMutation = `
mutation updateAnalytic(
  $uuid: ID!,
  $name: String!,
  $inputType: String!,
  $description: String!,
  $actions: [String],
  $analyticActions: [AnalyticActionsInput]!,
  $tags: [String]!,
  $categories: [String]!,
  $filter: String!,
  $context: [AnalyticContextInput]!,
  $level: Int!,
  $severity: SEVERITY,
  $snapshotFiles: [String]!
) {
  updateAnalytic(uuid: $uuid, input: {
    name: $name,
    inputType: $inputType,
    description: $description,
    actions: $actions,
    analyticActions: $analyticActions,
    categories: $categories,
    tags: $tags,
    filter: $filter,
    context: $context,
    level: $level,
    severity: $severity,
    snapshotFiles: $snapshotFiles
  }) {
    ...AnalyticFields
  }
}
` + analyticFields

const deleteAnalyticMutation = `
mutation deleteAnalytic($uuid: ID!) {
  deleteAnalytic(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *AnalyticResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AnalyticResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var result struct {
		CreateAnalytic analyticAPIModel `json:"createAnalytic"`
	}
	if err := r.client.Query(ctx, createAnalyticMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating analytic", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateAnalytic, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created analytic", map[string]any{"uuid": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AnalyticResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"uuid": data.ID.ValueString()}
	var result struct {
		GetAnalytic *analyticAPIModel `json:"getAnalytic"`
	}
	if err := r.client.Query(ctx, getAnalyticQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading analytic", err.Error())
		return
	}
	if result.GetAnalytic == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetAnalytic, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AnalyticResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UUID comes from state, not plan.
	var state AnalyticResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	vars["uuid"] = data.ID.ValueString()

	var result struct {
		UpdateAnalytic analyticAPIModel `json:"updateAnalytic"`
	}
	if err := r.client.Query(ctx, updateAnalyticMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating analytic", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateAnalytic, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AnalyticResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AnalyticResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"uuid": data.ID.ValueString()}
	if err := r.client.Query(ctx, deleteAnalyticMutation, vars, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting analytic", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted analytic", map[string]any{"uuid": data.ID.ValueString()})
}

func (r *AnalyticResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data AnalyticResourceModel
	data.ID = types.StringValue(req.ID)

	vars := map[string]any{"uuid": req.ID}
	var result struct {
		GetAnalytic *analyticAPIModel `json:"getAnalytic"`
	}
	if err := r.client.Query(ctx, getAnalyticQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error importing analytic", err.Error())
		return
	}
	if result.GetAnalytic == nil {
		resp.Diagnostics.AddError("Analytic not found", fmt.Sprintf("No analytic with UUID %q", req.ID))
		return
	}

	r.apiToState(ctx, &data, *result.GetAnalytic, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// ---------------------------------------------------------------------------
// API model (matches the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type analyticAPIModel struct {
	UUID            string                    `json:"uuid"`
	Name            string                    `json:"name"`
	InputType       string                    `json:"inputType"`
	Filter          string                    `json:"filter"`
	Description     string                    `json:"description"`
	Created         string                    `json:"created"`
	Updated         string                    `json:"updated"`
	Actions         []string                  `json:"actions"`
	AnalyticActions []analyticActionAPIModel  `json:"analyticActions"`
	Tags            []string                  `json:"tags"`
	Level           int64                     `json:"level"`
	Severity        string                    `json:"severity"`
	SnapshotFiles   []string                  `json:"snapshotFiles"`
	Context         []analyticContextAPIModel `json:"context"`
	Categories      []string                  `json:"categories"`
}

type analyticActionAPIModel struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

type analyticContextAPIModel struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *AnalyticResource) buildVariables(ctx context.Context, data AnalyticResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":      data.Name.ValueString(),
		"inputType": data.InputType.ValueString(),
		"filter":    data.Filter.ValueString(),
		"level":     data.Level.ValueInt64(),
		"severity":  data.Severity.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Simple string lists.
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	vars["categories"] = listToStrings(ctx, data.Categories, diags)
	vars["snapshotFiles"] = listToStrings(ctx, data.SnapshotFiles, diags)

	if !data.Actions.IsNull() {
		vars["actions"] = listToStrings(ctx, data.Actions, diags)
	}

	// Analytic actions.
	var actions []map[string]any
	if !data.AnalyticActions.IsNull() {
		var actionModels []analyticActionModel
		diags.Append(data.AnalyticActions.ElementsAs(ctx, &actionModels, false)...)
		for _, a := range actionModels {
			m := map[string]any{"name": a.Name.ValueString()}
			if !a.Parameters.IsNull() && len(a.Parameters.Elements()) > 0 {
				// Convert the map to a JSON-encoded string for the API.
				paramMap := make(map[string]string, len(a.Parameters.Elements()))
				diags.Append(a.Parameters.ElementsAs(ctx, &paramMap, false)...)
				jsonBytes, err := json.Marshal(paramMap)
				if err != nil {
					diags.AddError("Error encoding parameters", err.Error())
					return nil
				}
				m["parameters"] = string(jsonBytes)
			}
			actions = append(actions, m)
		}
	}
	if actions == nil {
		actions = []map[string]any{}
	}
	vars["analyticActions"] = actions

	// Context.
	var ctxEntries []map[string]any
	if !data.Context.IsNull() {
		var contextModels []analyticContextModel
		diags.Append(data.Context.ElementsAs(ctx, &contextModels, false)...)
		for _, c := range contextModels {
			ctxEntries = append(ctxEntries, map[string]any{
				"name":  c.Name.ValueString(),
				"type":  c.Type.ValueString(),
				"exprs": listToStrings(ctx, c.Exprs, diags),
			})
		}
	}
	if ctxEntries == nil {
		ctxEntries = []map[string]any{}
	}
	vars["context"] = ctxEntries

	return vars
}

// apiToState maps the API response into the Terraform state model.
func (r *AnalyticResource) apiToState(_ context.Context, data *AnalyticResourceModel, api analyticAPIModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.InputType = types.StringValue(api.InputType)
	data.Filter = types.StringValue(api.Filter)
	data.Level = types.Int64Value(api.Level)
	data.Severity = types.StringValue(api.Severity)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}

	data.Tags = stringsToList(api.Tags)
	data.Categories = stringsToList(api.Categories)
	data.SnapshotFiles = stringsToList(api.SnapshotFiles)

	// actions is Optional — preserve null when the API returns an empty array
	// so the plan doesn't show a diff from null → [].
	if len(api.Actions) == 0 {
		data.Actions = types.ListNull(types.StringType)
	} else {
		data.Actions = stringsToList(api.Actions)
	}

	// Analytic actions.
	actionAttrTypes := map[string]attr.Type{
		"name":       types.StringType,
		"parameters": types.MapType{ElemType: types.StringType},
	}
	var actionVals []attr.Value
	for _, a := range api.AnalyticActions {
		paramVal := types.MapNull(types.StringType)
		if a.Parameters != "" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(a.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", a.Parameters, err.Error()))
				return
			}
			paramElements := make(map[string]attr.Value, len(paramMap))
			for k, v := range paramMap {
				paramElements[k] = types.StringValue(v)
			}
			mapVal, d := types.MapValue(types.StringType, paramElements)
			diags.Append(d...)
			paramVal = mapVal
		}
		actionVals = append(actionVals, types.ObjectValueMust(actionAttrTypes, map[string]attr.Value{
			"name":       types.StringValue(a.Name),
			"parameters": paramVal,
		}))
	}
	if len(actionVals) == 0 {
		data.AnalyticActions = types.ListValueMust(types.ObjectType{AttrTypes: actionAttrTypes}, []attr.Value{})
	} else {
		actionList, d := types.ListValue(types.ObjectType{AttrTypes: actionAttrTypes}, actionVals)
		diags.Append(d...)
		data.AnalyticActions = actionList
	}

	// Context.
	ctxAttrTypes := map[string]attr.Type{
		"name":  types.StringType,
		"type":  types.StringType,
		"exprs": types.ListType{ElemType: types.StringType},
	}
	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(ctxAttrTypes, map[string]attr.Value{
			"name":  types.StringValue(c.Name),
			"type":  types.StringValue(c.Type),
			"exprs": stringsToList(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		data.Context = types.ListValueMust(types.ObjectType{AttrTypes: ctxAttrTypes}, []attr.Value{})
	} else {
		ctxList, d := types.ListValue(types.ObjectType{AttrTypes: ctxAttrTypes}, ctxVals)
		diags.Append(d...)
		data.Context = ctxList
	}
}
