// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"

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

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &PlanResource{}
var _ resource.ResourceWithImportState = &PlanResource{}

func NewPlanResource() resource.Resource {
	return &PlanResource{}
}

// PlanResource manages a Jamf Protect plan.
type PlanResource struct {
	service *jamfprotect.Service
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
			"removable_storage_control_set": schema.StringAttribute{
				MarkdownDescription: "The ID of the USB control set to associate with this plan.",
				Optional:            true,
			},
			"analytic_sets": schema.SetAttribute{
				MarkdownDescription: "Analytic set UUIDs to include in this plan. The type is always `Report`.",
				Optional:            true,
				ElementType:         types.StringType,
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
			"endpoint_threat_prevention": schema.StringAttribute{
				MarkdownDescription: "Endpoint threat prevention setting for the plan. Defaults to `BlockAndReport`. Values map to signatures feed modes: `BlockAndReport` -> `blocking`, `Report` -> `reportOnly`, `Disable` -> `disabled`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("BlockAndReport"),
				Validators: []validator.String{
					stringvalidator.OneOf("BlockAndReport", "Report", "Disable"),
				},
			},
			"advanced_threat_controls": schema.StringAttribute{
				MarkdownDescription: "Advanced Threat Controls setting for the plan. Values map to the managed analytic set named `Advanced Threat Controls`: `BlockAndReport` -> `Prevent`, `ReportOnly` -> `Report`, `Disable` -> omit.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Validators: []validator.String{
					stringvalidator.OneOf("BlockAndReport", "ReportOnly", "Disable"),
				},
			},
			"tamper_prevention": schema.StringAttribute{
				MarkdownDescription: "Tamper Prevention setting for the plan. Values map to the managed analytic set named `Tamper Prevention`: `BlockAndReport` -> `Prevent`, `Disable` -> omit.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Validators: []validator.String{
					stringvalidator.OneOf("BlockAndReport", "Disable"),
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
	r.service = jamfprotect.NewService(client)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *PlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
