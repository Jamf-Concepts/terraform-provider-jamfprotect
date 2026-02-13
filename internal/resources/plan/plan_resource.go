// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"
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

var _ resource.Resource = &PlanResource{}
var _ resource.ResourceWithImportState = &PlanResource{}

func NewPlanResource() resource.Resource {
	return &PlanResource{}
}

// PlanResource manages a Jamf Protect plan.
type PlanResource struct {
	client *client.Client
}

func (r *PlanResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan"
}

func (r *PlanResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a plan in Jamf Protect. Plans define the security configuration deployed to endpoints, including analytic sets, action configurations, telemetry settings, and more.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the plan.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hash": schema.StringAttribute{
				MarkdownDescription: "The configuration hash of the plan.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the plan.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the plan.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"log_level": schema.StringAttribute{
				MarkdownDescription: "The log level for the plan. Defaults to `ERROR`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ERROR"),
				Validators: []validator.String{
					stringvalidator.OneOf("DISABLED", "ERROR", "WARNING", "INFO", "DEBUG"),
				},
			},
			"auto_update": schema.BoolAttribute{
				MarkdownDescription: "Whether to enable auto-updates for endpoints using this plan. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"action_configs": schema.StringAttribute{
				MarkdownDescription: "The ID of the action configuration to associate with this plan.",
				Required:            true,
			},
			"exception_sets": schema.ListAttribute{
				MarkdownDescription: "A list of exception set IDs to associate with this plan.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"telemetry": schema.StringAttribute{
				MarkdownDescription: "The ID of the legacy telemetry configuration.",
				Optional:            true,
			},
			"telemetry_v2": schema.StringAttribute{
				MarkdownDescription: "The ID of the v2 telemetry configuration.",
				Optional:            true,
			},
			"usb_control_set": schema.StringAttribute{
				MarkdownDescription: "The ID of the USB control set to associate with this plan.",
				Optional:            true,
			},
			"analytic_sets": schema.ListNestedAttribute{
				MarkdownDescription: "Analytic sets to include in this plan.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of analytic set.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("Report", "Prevent"),
							},
						},
						"analytic_set": schema.StringAttribute{
							MarkdownDescription: "The UUID of the analytic set.",
							Required:            true,
						},
					},
				},
			},
			"comms_config": schema.SingleNestedAttribute{
				MarkdownDescription: "Communications configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"fqdn": schema.StringAttribute{
						MarkdownDescription: "The fully qualified domain name for communications.",
						Required:            true,
					},
					"protocol": schema.StringAttribute{
						MarkdownDescription: "The protocol to use. Defaults to `mqtt`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("mqtt"),
						Validators: []validator.String{
							stringvalidator.OneOf("mqtt"),
						},
					},
				},
			},
			"info_sync": schema.SingleNestedAttribute{
				MarkdownDescription: "Info sync configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"attrs": schema.ListAttribute{
						MarkdownDescription: "A list of attribute names to sync.",
						Required:            true,
						ElementType:         types.StringType,
					},
					"insights_sync_interval": schema.Int64Attribute{
						MarkdownDescription: "The interval in seconds for insights data synchronization.",
						Required:            true,
					},
				},
			},
			"signatures_feed_config": schema.SingleNestedAttribute{
				MarkdownDescription: "Signatures feed configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						MarkdownDescription: "The signatures feed mode. Defaults to `blocking`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("blocking"),
						Validators: []validator.String{
							stringvalidator.OneOf("blocking", "monitoring", "off"),
						},
					},
				},
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

func (r *PlanResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PlanResourceModel
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
		CreatePlan planAPIModel `json:"createPlan"`
	}
	if err := r.client.Query(ctx, createPlanMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreatePlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created plan", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PlanResourceModel
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
		GetPlan *planAPIModel `json:"getPlan"`
	}
	if err := r.client.Query(ctx, getPlanQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading plan", err.Error())
		return
	}
	if result.GetPlan == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetPlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state PlanResourceModel
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
		UpdatePlan planAPIModel `json:"updatePlan"`
	}
	if err := r.client.Query(ctx, updatePlanMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdatePlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PlanResourceModel
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
	if err := r.client.Query(ctx, deletePlanMutation, vars, nil); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "plan already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting plan", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted plan", map[string]any{"id": data.ID.ValueString()})
}

func (r *PlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
