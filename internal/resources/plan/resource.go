// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/common/validators"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &PlanResource{}
var _ resource.ResourceWithImportState = &PlanResource{}
var _ resource.ResourceWithIdentity = &PlanResource{}

// NewPlanResource returns a new plan resource.
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

// Schema defines the plan schema.
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
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the plan.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the plan.",
				Optional:            true,
				Computed:            true,
			},
			"log_level": schema.StringAttribute{
				MarkdownDescription: "The log level for the plan. Valid options are: " + common.FormatOptions(logLevelUIOptions) + ". Defaults to `Error`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Error"),
				Validators: []validator.String{
					stringvalidator.OneOf(logLevelUIOptions...),
				},
			},
			"auto_update": schema.BoolAttribute{
				MarkdownDescription: "Whether to enable auto-updates for endpoints using this plan. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"action_configuration": schema.StringAttribute{
				MarkdownDescription: "The ID of the action configuration to associate with this plan.",
				Required:            true,
			},
			"exception_sets": schema.SetAttribute{
				MarkdownDescription: "A set of exception set IDs to associate with this plan.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(validators.UUID())},
			},
			"telemetry": schema.StringAttribute{
				MarkdownDescription: "The ID of the telemetry configuration.",
				Optional:            true,
			},
			"removable_storage_control_set": schema.StringAttribute{
				MarkdownDescription: "The ID of the USB control set to associate with this plan.",
				Optional:            true,
			},
			"analytic_sets": schema.SetAttribute{
				MarkdownDescription: "A set of analytic set IDs to include in this plan.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(validators.UUID())},
			},
			"communications_protocol": schema.StringAttribute{
				MarkdownDescription: "The communications protocol to use. Valid options are: " + common.FormatOptions(communicationsProtocolUIOptions) + ". Defaults to `MQTT:443`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("MQTT:443"),
				Validators: []validator.String{
					stringvalidator.OneOf(communicationsProtocolUIOptions...),
				},
			},
			"reporting_interval": schema.Int64Attribute{
				MarkdownDescription: "The reporting interval in minutes.",
				Required:            true,
			},
			"report_architecture": schema.BoolAttribute{
				MarkdownDescription: "Report the device architecture.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_hostname": schema.BoolAttribute{
				MarkdownDescription: "Report the device hostname.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_kernel_version": schema.BoolAttribute{
				MarkdownDescription: "Report the kernel version.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_memory_size": schema.BoolAttribute{
				MarkdownDescription: "Report the device memory size.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_model_name": schema.BoolAttribute{
				MarkdownDescription: "Report the device model name.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_serial_number": schema.BoolAttribute{
				MarkdownDescription: "Report the device serial number.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"compliance_baseline_reporting": schema.BoolAttribute{
				MarkdownDescription: "Report compliance baseline data.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"report_os_version": schema.BoolAttribute{
				MarkdownDescription: "Report the OS version details.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"endpoint_threat_prevention": schema.StringAttribute{
				MarkdownDescription: "Endpoint threat prevention setting for the plan. Valid options are: " + common.FormatOptions(endpointThreatPreventionUIOptions) + ". Defaults to `Block and report`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Block and report"),
				Validators: []validator.String{
					stringvalidator.OneOf(endpointThreatPreventionUIOptions...),
				},
			},
			"advanced_threat_controls": schema.StringAttribute{
				MarkdownDescription: "Advanced Threat Controls setting for the plan. Valid options are: " + common.FormatOptions(advancedThreatControlsUIOptions) + ".",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Validators: []validator.String{
					stringvalidator.OneOf(advancedThreatControlsUIOptions...),
				},
			},
			"tamper_prevention": schema.StringAttribute{
				MarkdownDescription: "Tamper Prevention setting for the plan. Valid options are: " + common.FormatOptions(tamperPreventionUIOptions) + ".",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Validators: []validator.String{
					stringvalidator.OneOf(tamperPreventionUIOptions...),
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

// IdentitySchema defines the identity attributes for plans.
func (r *PlanResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the plan.",
			},
		},
	}
}

// Configure prepares the plan service client.
func (r *PlanResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

// ImportState supports importing plans by ID.
func (r *PlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
