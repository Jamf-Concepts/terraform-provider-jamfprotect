// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &AnalyticResource{}
var _ resource.ResourceWithImportState = &AnalyticResource{}

func NewAnalyticResource() resource.Resource {
	return &AnalyticResource{}
}

// AnalyticResource manages a Jamf Protect custom analytic.
type AnalyticResource struct {
	service *jamfprotect.Service
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
			"sensor_type": schema.StringAttribute{
				MarkdownDescription: "The sensor type for the analytic. Determines which endpoint event stream the analytic monitors.",
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
				Required:            true,
			},
			"label": schema.StringAttribute{
				MarkdownDescription: "Display label for the analytic (read-only).",
				Computed:            true,
			},
			"long_description": schema.StringAttribute{
				MarkdownDescription: "Long-form description for the analytic (read-only).",
				Computed:            true,
			},
			"predicate": schema.StringAttribute{
				MarkdownDescription: "The predicate expression for the analytic.",
				Required:            true,
			},
			"level": schema.Int64Attribute{
				MarkdownDescription: "The log level (integer) for the analytic. Valid values are 0-10.",
				Required:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 10),
				},
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
			"add_to_jamf_pro_smart_group": schema.BoolAttribute{
				MarkdownDescription: "Whether to add the device to a Jamf Pro Smart Group when this analytic triggers.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"jamf_pro_smart_group_identifier": schema.StringAttribute{
				MarkdownDescription: "Identifier for the Jamf Pro extension attribute (only used when adding to a Smart Group).",
				Optional:            true,
			},
			"context_item": schema.ListNestedAttribute{
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
						"expressions": schema.ListAttribute{
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
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
			"tenant_actions": schema.ListNestedAttribute{
				MarkdownDescription: "Tenant-level action overrides (Jamf-managed analytics).",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "The action name (e.g. `Log`, `SmartGroup`, `Webhook`).",
							Computed:            true,
						},
						"parameters": schema.MapAttribute{
							MarkdownDescription: "Action parameters as key-value pairs (e.g. `{id = \"smartgroup\"}`).",
							Computed:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"tenant_severity": schema.StringAttribute{
				MarkdownDescription: "Tenant-level severity override (Jamf-managed analytics).",
				Computed:            true,
			},
			"jamf": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether the analytic is Jamf-managed (read-only).",
				Computed:            true,
			},
			"remediation": schema.StringAttribute{
				MarkdownDescription: "Remediation guidance associated with the analytic (read-only).",
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
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.service = jamfprotect.NewService(client)
}

func (r *AnalyticResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
