// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &ActionConfigResource{}
var _ resource.ResourceWithImportState = &ActionConfigResource{}

var (
	extendedDataAttributeOptions = []string{
		"File",
		"Process",
		"User",
		"Group",
		"Blocked Process",
		"Blocked Binary",
		"Source Process",
		"Destination Process",
		"Sha1",
		"Sha256",
		"Extended Attributes",
		"Is App Bundle",
		"Is Screenshot",
		"Is Quarantined",
		"Is Download",
		"Is Directory",
		"Downloaded From",
		"Signing Information",
		"Args",
		"Is GUI App",
		"App Path",
		"Binary",
		"Parent",
		"Process Group Leader",
		"Name",
	}
	endpointAlertSeverities = []string{"high", "medium", "low", "informational"}
	endpointLogTypes        = []string{"telemetry", "unified_logs"}
	httpMethodOptions       = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	syslogProtocolOptions   = []string{"tls", "tcp", "udp"}
)

func NewActionConfigResource() resource.Resource {
	return &ActionConfigResource{}
}

// ActionConfigResource manages a Jamf Protect action configuration.
type ActionConfigResource struct {
	service *jamfprotect.Service
}

func (r *ActionConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_action_configuration"
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
				Default:             stringdefault.StaticString(""),
			},
			"alert_data_collection": schema.SingleNestedAttribute{
				MarkdownDescription: "Alert data collection options from the Jamf Protect UI.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"binary_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for binary events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"synthetic_click_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for synthetic click events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"download_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for download events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"file_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for file events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"file_system_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for file system events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"group_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for group events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"process_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for process events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"process_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for process metadata. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"screenshot_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for screenshot events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"user_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for user events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"gatekeeper_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for gatekeeper events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
					"keylog_register_event_included_data_attributes": schema.SetAttribute{
						MarkdownDescription: "Included data attributes for keylog register events. Valid options are: " + common.FormatOptions(extendedDataAttributeOptions) + ".",
						Required:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(extendedDataAttributeOptions...)),
						},
					},
				},
			},
			"http_endpoints": schema.ListNestedAttribute{
				MarkdownDescription: "HTTP data endpoints configured in the Jamf Protect UI.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"collect_alerts": schema.SetAttribute{
							MarkdownDescription: "Alert severities collected by this endpoint. Valid options are: " + common.FormatOptions(endpointAlertSeverities) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointAlertSeverities...)),
							},
						},
						"collect_logs": schema.SetAttribute{
							MarkdownDescription: "Log types collected by this endpoint. Valid options are: " + common.FormatOptions(endpointLogTypes) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointLogTypes...)),
							},
						},
						"events_per_batch": schema.Int64Attribute{
							MarkdownDescription: "Maximum number of events per batch.",
							Optional:            true,
						},
						"batching_window_seconds": schema.Int64Attribute{
							MarkdownDescription: "Maximum time in seconds between when an event occurs and when it is sent.",
							Optional:            true,
						},
						"event_delimiter": schema.StringAttribute{
							MarkdownDescription: "Delimiter used between batched records.",
							Optional:            true,
						},
						"max_batch_size_bytes": schema.Int64Attribute{
							MarkdownDescription: "Maximum batch size in bytes.",
							Optional:            true,
						},
						"url": schema.StringAttribute{
							MarkdownDescription: "HTTP destination URL.",
							Optional:            true,
						},
						"method": schema.StringAttribute{
							MarkdownDescription: "HTTP request method. Valid options are: " + common.FormatOptions(httpMethodOptions) + ".",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(httpMethodOptions...),
							},
						},
						"headers": schema.ListNestedAttribute{
							MarkdownDescription: "HTTP headers.",
							Optional:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"header": schema.StringAttribute{Optional: true},
									"value":  schema.StringAttribute{Optional: true},
								},
							},
						},
					},
				},
			},
			"kafka_endpoints": schema.ListNestedAttribute{
				MarkdownDescription: "Kafka data endpoints configured in the Jamf Protect UI.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"collect_alerts": schema.SetAttribute{
							MarkdownDescription: "Alert severities collected by this endpoint. Valid options are: " + common.FormatOptions(endpointAlertSeverities) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointAlertSeverities...)),
							},
						},
						"collect_logs": schema.SetAttribute{
							MarkdownDescription: "Log types collected by this endpoint. Valid options are: " + common.FormatOptions(endpointLogTypes) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointLogTypes...)),
							},
						},
						"host": schema.StringAttribute{
							MarkdownDescription: "Kafka host.",
							Optional:            true,
						},
						"port": schema.Int64Attribute{
							MarkdownDescription: "Kafka port.",
							Optional:            true,
							Validators: []validator.Int64{
								int64validator.Between(0, 65535),
							},
						},
						"topic": schema.StringAttribute{
							MarkdownDescription: "Kafka topic.",
							Optional:            true,
						},
						"client_cn": schema.StringAttribute{
							MarkdownDescription: "Kafka client certificate CN.",
							Optional:            true,
						},
						"server_cn": schema.StringAttribute{
							MarkdownDescription: "Kafka server certificate CN.",
							Optional:            true,
						},
					},
				},
			},
			"syslog_endpoints": schema.ListNestedAttribute{
				MarkdownDescription: "Syslog data endpoints configured in the Jamf Protect UI.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"collect_alerts": schema.SetAttribute{
							MarkdownDescription: "Alert severities collected by this endpoint. Valid options are: " + common.FormatOptions(endpointAlertSeverities) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointAlertSeverities...)),
							},
						},
						"collect_logs": schema.SetAttribute{
							MarkdownDescription: "Log types collected by this endpoint. Valid options are: " + common.FormatOptions(endpointLogTypes) + ".",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointLogTypes...)),
							},
						},
						"host": schema.StringAttribute{
							MarkdownDescription: "Syslog host.",
							Optional:            true,
						},
						"port": schema.Int64Attribute{
							MarkdownDescription: "Syslog port.",
							Optional:            true,
							Validators: []validator.Int64{
								int64validator.Between(0, 65535),
							},
						},
						"protocol": schema.StringAttribute{
							MarkdownDescription: "Syslog protocol. Valid options are: " + common.FormatOptions(syslogProtocolOptions) + ".",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(syslogProtocolOptions...),
							},
						},
					},
				},
			},
			"log_file_endpoint": schema.SingleNestedAttribute{
				MarkdownDescription: "Log file data endpoint configured in the Jamf Protect UI.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"collect_alerts": schema.SetAttribute{
						MarkdownDescription: "Alert severities collected by this endpoint. Valid options are: " + common.FormatOptions(endpointAlertSeverities) + ".",
						Optional:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointAlertSeverities...)),
						},
					},
					"collect_logs": schema.SetAttribute{
						MarkdownDescription: "Log types collected by this endpoint. Valid options are: " + common.FormatOptions(endpointLogTypes) + ".",
						Optional:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointLogTypes...)),
						},
					},
					"path": schema.StringAttribute{
						MarkdownDescription: "Log file path.",
						Optional:            true,
					},
					"ownership": schema.StringAttribute{
						MarkdownDescription: "User and group that own the log file.",
						Optional:            true,
					},
					"permissions": schema.StringAttribute{
						MarkdownDescription: "Log file permissions.",
						Optional:            true,
					},
					"max_file_size_mb": schema.Int64Attribute{
						MarkdownDescription: "Maximum file size in MB before rotating.",
						Optional:            true,
					},
					"max_backups": schema.Int64Attribute{
						MarkdownDescription: "Maximum number of backup files to keep.",
						Optional:            true,
					},
				},
			},
			"jamf_protect_cloud_endpoint": schema.SingleNestedAttribute{
				MarkdownDescription: "Jamf Protect Cloud data endpoint configured in the Jamf Protect UI.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"collect_alerts": schema.SetAttribute{
						MarkdownDescription: "Alert severities collected by this endpoint. Valid options are: " + common.FormatOptions(endpointAlertSeverities) + ".",
						Optional:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointAlertSeverities...)),
						},
					},
					"collect_logs": schema.SetAttribute{
						MarkdownDescription: "Log types collected by this endpoint. Valid options are: " + common.FormatOptions(endpointLogTypes) + ".",
						Optional:            true,
						ElementType:         types.StringType,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(stringvalidator.OneOf(endpointLogTypes...)),
						},
					},
					"destination_filter": schema.StringAttribute{
						MarkdownDescription: "Destination filter (if configured).",
						Optional:            true,
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

func (r *ActionConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ActionConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
