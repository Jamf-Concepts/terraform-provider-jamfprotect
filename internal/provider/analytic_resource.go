// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
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
// CRUD
// ---------------------------------------------------------------------------

func (r *AnalyticResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AnalyticResourceModel
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

	readTimeout, diags := data.Timeouts.Read(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

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

	deleteTimeout, diags := data.Timeouts.Delete(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

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
