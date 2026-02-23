// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &PlansDataSource{}

func NewPlansDataSource() datasource.DataSource {
	return &PlansDataSource{}
}

// PlansDataSource lists all plans in Jamf Protect.
type PlansDataSource struct {
	service *jamfprotect.Service
}

// PlansDataSourceModel maps the data source schema.
type PlansDataSourceModel struct {
	Plans []PlanDataSourceItemModel `tfsdk:"plans"`
}

// PlanDataSourceItemModel maps a single plan item (read-only, no timeouts).
type PlanDataSourceItemModel struct {
	ID                       types.String `tfsdk:"id"`
	Hash                     types.String `tfsdk:"hash"`
	Name                     types.String `tfsdk:"name"`
	Description              types.String `tfsdk:"description"`
	LogLevel                 types.String `tfsdk:"log_level"`
	AutoUpdate               types.Bool   `tfsdk:"auto_update"`
	ActionConfiguration      types.String `tfsdk:"action_configuration"`
	ExceptionSets            types.Set    `tfsdk:"exception_sets"`
	Telemetry                types.String `tfsdk:"telemetry"`
	USBControlSet            types.String `tfsdk:"removable_storage_control_set"`
	AnalyticSets             types.List   `tfsdk:"analytic_sets"`
	CommunicationsProtocol   types.String `tfsdk:"communications_protocol"`
	ReportingInterval        types.Int64  `tfsdk:"reporting_interval"`
	ReportArchitecture       types.Bool   `tfsdk:"report_architecture"`
	ReportHostname           types.Bool   `tfsdk:"report_hostname"`
	ReportKernelVersion      types.Bool   `tfsdk:"report_kernel_version"`
	ReportMemorySize         types.Bool   `tfsdk:"report_memory_size"`
	ReportModelName          types.Bool   `tfsdk:"report_model_name"`
	ReportSerialNumber       types.Bool   `tfsdk:"report_serial_number"`
	ComplianceBaseline       types.Bool   `tfsdk:"compliance_baseline_reporting"`
	ReportOSVersion          types.Bool   `tfsdk:"report_os_version"`
	EndpointThreatPrevention types.String `tfsdk:"endpoint_threat_prevention"`
	AdvancedThreatControls   types.String `tfsdk:"advanced_threat_controls"`
	TamperPrevention         types.String `tfsdk:"tamper_prevention"`
	Created                  types.String `tfsdk:"created"`
	Updated                  types.String `tfsdk:"updated"`
}

func (d *PlansDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plans"
}

func (d *PlansDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all plans in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"plans": schema.ListNestedAttribute{
				MarkdownDescription: "The list of plans.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: planDataSourceAttributes(),
				},
			},
		},
	}
}

func planDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the plan.",
			Computed:            true,
		},
		"hash": schema.StringAttribute{
			MarkdownDescription: "The configuration hash of the plan.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the plan.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the plan.",
			Computed:            true,
		},
		"log_level": schema.StringAttribute{
			MarkdownDescription: "The log level for the plan. Values: `Error`, `Warning`, `Info`, `Debug`, `Verbose`.",
			Computed:            true,
		},
		"auto_update": schema.BoolAttribute{
			MarkdownDescription: "Whether auto-updates are enabled for endpoints using this plan.",
			Computed:            true,
		},
		"action_configuration": schema.StringAttribute{
			MarkdownDescription: "The ID of the action configuration associated with this plan.",
			Computed:            true,
		},
		"exception_sets": schema.SetAttribute{
			MarkdownDescription: "A set of exception set IDs associated with this plan.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"telemetry": schema.StringAttribute{
			MarkdownDescription: "The ID of the telemetry configuration.",
			Computed:            true,
		},
		"removable_storage_control_set": schema.StringAttribute{
			MarkdownDescription: "The ID of the USB control set associated with this plan.",
			Computed:            true,
		},
		"analytic_sets": schema.ListAttribute{
			MarkdownDescription: "Analytic set UUIDs included in this plan. The type is always `Report`.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"communications_protocol": schema.StringAttribute{
			MarkdownDescription: "The communications protocol used by the plan. Values: `MQTT:443`, `WebSocket/MQTT:443`.",
			Computed:            true,
		},
		"reporting_interval": schema.Int64Attribute{
			MarkdownDescription: "The reporting interval in minutes.",
			Computed:            true,
		},
		"report_architecture": schema.BoolAttribute{
			MarkdownDescription: "Whether device architecture reporting is enabled.",
			Computed:            true,
		},
		"report_hostname": schema.BoolAttribute{
			MarkdownDescription: "Whether device hostname reporting is enabled.",
			Computed:            true,
		},
		"report_kernel_version": schema.BoolAttribute{
			MarkdownDescription: "Whether kernel version reporting is enabled.",
			Computed:            true,
		},
		"report_memory_size": schema.BoolAttribute{
			MarkdownDescription: "Whether memory size reporting is enabled.",
			Computed:            true,
		},
		"report_model_name": schema.BoolAttribute{
			MarkdownDescription: "Whether model name reporting is enabled.",
			Computed:            true,
		},
		"report_serial_number": schema.BoolAttribute{
			MarkdownDescription: "Whether serial number reporting is enabled.",
			Computed:            true,
		},
		"compliance_baseline_reporting": schema.BoolAttribute{
			MarkdownDescription: "Whether compliance baseline reporting is enabled.",
			Computed:            true,
		},
		"report_os_version": schema.BoolAttribute{
			MarkdownDescription: "Whether OS version reporting is enabled.",
			Computed:            true,
		},
		"endpoint_threat_prevention": schema.StringAttribute{
			MarkdownDescription: "Endpoint threat prevention setting for the plan. Values: `Block and report`, `Report only`, `Disable`.",
			Computed:            true,
		},
		"advanced_threat_controls": schema.StringAttribute{
			MarkdownDescription: "Advanced Threat Controls setting for the plan. Values: `Block and report`, `Report only`, `Disable`.",
			Computed:            true,
		},
		"tamper_prevention": schema.StringAttribute{
			MarkdownDescription: "Tamper Prevention setting for the plan. Values: `Block and report`, `Disable`.",
			Computed:            true,
		},
		"created": schema.StringAttribute{
			MarkdownDescription: "The creation timestamp.",
			Computed:            true,
		},
		"updated": schema.StringAttribute{
			MarkdownDescription: "The last-updated timestamp.",
			Computed:            true,
		},
	}
}

func (d *PlansDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *PlansDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PlansDataSourceModel

	allPlans, err := d.service.ListPlans(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing plans", err.Error())
		return
	}

	tflog.Trace(ctx, "listed plans", map[string]any{"count": len(allPlans)})

	// Convert API models to data source models.
	plans := make([]PlanDataSourceItemModel, 0, len(allPlans))
	for _, api := range allPlans {
		item := planAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		plans = append(plans, item)
	}
	data.Plans = plans

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
