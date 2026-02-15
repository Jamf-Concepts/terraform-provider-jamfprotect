// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &TelemetryV2Resource{}
var _ resource.ResourceWithImportState = &TelemetryV2Resource{}

func NewTelemetryV2Resource() resource.Resource {
	return &TelemetryV2Resource{}
}

// TelemetryV2Resource manages a Jamf Protect telemetry v2 configuration.
type TelemetryV2Resource struct {
	service *jamfprotect.Service
}

func (r *TelemetryV2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_telemetry"
}

func (r *TelemetryV2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a telemetry v2 configuration in Jamf Protect. Telemetry configurations define which endpoint security events, log files, and performance metrics are collected from managed endpoints.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the telemetry v2 configuration.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the telemetry v2 configuration.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the telemetry v2 configuration.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"log_file_path": schema.ListAttribute{
				MarkdownDescription: "A list of log file paths to collect from endpoints.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"collect_diagnostic_and_crash_reports": schema.BoolAttribute{
				MarkdownDescription: "Whether diagnostic and crash report collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"collect_performance_metrics": schema.BoolAttribute{
				MarkdownDescription: "Whether performance metrics collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"file_hashes": schema.BoolAttribute{
				MarkdownDescription: "Whether file hashing is enabled for telemetry events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_applications_and_processes": schema.BoolAttribute{
				MarkdownDescription: "Collect application and process events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_access_and_authentication": schema.BoolAttribute{
				MarkdownDescription: "Collect access and authentication events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_users_and_groups": schema.BoolAttribute{
				MarkdownDescription: "Collect user and group management events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_persistence": schema.BoolAttribute{
				MarkdownDescription: "Collect persistence-related events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_hardware_and_software": schema.BoolAttribute{
				MarkdownDescription: "Collect hardware and software events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_apple_security": schema.BoolAttribute{
				MarkdownDescription: "Collect Apple security events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_system": schema.BoolAttribute{
				MarkdownDescription: "Collect system events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last update timestamp.",
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

func (r *TelemetryV2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TelemetryV2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
