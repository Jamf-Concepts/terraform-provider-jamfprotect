// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
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
	ExceptionSets            types.List   `tfsdk:"exception_sets"`
	Telemetry                types.String `tfsdk:"telemetry"`
	USBControlSet            types.String `tfsdk:"removable_storage_control_set"`
	AnalyticSets             types.Set    `tfsdk:"analytic_sets"`
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
			MarkdownDescription: "The log level for the plan.",
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
		"exception_sets": schema.ListAttribute{
			MarkdownDescription: "A list of exception set IDs associated with this plan.",
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
		"analytic_sets": schema.SetAttribute{
			MarkdownDescription: "Analytic set UUIDs included in this plan. The type is always `Report`.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"communications_protocol": schema.StringAttribute{
			MarkdownDescription: "The communications protocol used by the plan.",
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
			MarkdownDescription: "Endpoint threat prevention setting for the plan.",
			Computed:            true,
		},
		"advanced_threat_controls": schema.StringAttribute{
			MarkdownDescription: "Advanced Threat Controls setting for the plan.",
			Computed:            true,
		},
		"tamper_prevention": schema.StringAttribute{
			MarkdownDescription: "Tamper Prevention setting for the plan.",
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
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	d.service = jamfprotect.NewService(client)
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

// planAPIToDataSourceItem maps a plan to PlanDataSourceItemModel.
func planAPIToDataSourceItem(api jamfprotect.Plan, _ *diag.Diagnostics) PlanDataSourceItemModel {
	item := PlanDataSourceItemModel{
		ID:         types.StringValue(api.ID),
		Hash:       types.StringValue(api.Hash),
		Name:       types.StringValue(api.Name),
		AutoUpdate: types.BoolValue(api.AutoUpdate),
		Created:    types.StringValue(api.Created),
		Updated:    types.StringValue(api.Updated),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	if api.LogLevel != "" {
		item.LogLevel = types.StringValue(api.LogLevel)
	} else {
		item.LogLevel = types.StringNull()
	}

	// Action configuration.
	if api.ActionConfigs != nil {
		item.ActionConfiguration = types.StringValue(api.ActionConfigs.ID)
	} else {
		item.ActionConfiguration = types.StringNull()
	}

	// Exception sets.
	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		item.ExceptionSets = common.StringsToList(uuids)
	} else {
		item.ExceptionSets = types.ListNull(types.StringType)
	}

	// Telemetry reference.
	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		item.Telemetry = types.StringValue(api.TelemetryV2.ID)
	} else {
		item.Telemetry = types.StringNull()
	}

	// USB control set.
	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		item.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		item.USBControlSet = types.StringNull()
	}

	// Analytic sets (exclude managed ones with dedicated attributes).
	filteredAnalyticSets := filterManagedAnalyticSetEntries(api.AnalyticSets)
	if len(filteredAnalyticSets) > 0 {
		uuids := make([]string, len(filteredAnalyticSets))
		for i, as := range filteredAnalyticSets {
			uuids[i] = as.AnalyticSet.UUID
		}
		item.AnalyticSets = common.StringsToSet(uuids)
	} else {
		item.AnalyticSets = types.SetNull(types.StringType)
	}

	// Communications protocol.
	if api.CommsConfig != nil && api.CommsConfig.Protocol != "" {
		item.CommunicationsProtocol = types.StringValue(api.CommsConfig.Protocol)
	} else {
		item.CommunicationsProtocol = types.StringNull()
	}

	// Info sync reporting flags.
	setReportingFlagsDataSource(&item, api.InfoSync)

	// Endpoint threat prevention setting.
	if api.SignaturesFeedConfig != nil {
		if endpointThreatPrevention, ok := modeToEndpointThreatPrevention(api.SignaturesFeedConfig.Mode); ok {
			item.EndpointThreatPrevention = types.StringValue(endpointThreatPrevention)
		} else {
			item.EndpointThreatPrevention = types.StringNull()
		}
	} else {
		item.EndpointThreatPrevention = types.StringNull()
	}

	item.AdvancedThreatControls = resolveManagedAnalyticSetState(api.AnalyticSets, advancedThreatControlsName, true, nil)
	item.TamperPrevention = resolveManagedAnalyticSetState(api.AnalyticSets, tamperPreventionName, false, nil)

	return item
}

func setReportingFlagsDataSource(item *PlanDataSourceItemModel, infoSync *jamfprotect.PlanInfoSync) {
	if infoSync == nil {
		item.ReportingInterval = types.Int64Null()
		item.ReportArchitecture = types.BoolValue(false)
		item.ReportHostname = types.BoolValue(false)
		item.ReportKernelVersion = types.BoolValue(false)
		item.ReportMemorySize = types.BoolValue(false)
		item.ReportModelName = types.BoolValue(false)
		item.ReportSerialNumber = types.BoolValue(false)
		item.ComplianceBaseline = types.BoolValue(false)
		item.ReportOSVersion = types.BoolValue(false)
		return
	}

	item.ReportingInterval = types.Int64Value(infoSync.InsightsSyncInterval / 60)

	attrSet := map[string]struct{}{}
	for _, attr := range infoSync.Attrs {
		attrSet[attr] = struct{}{}
	}

	item.ReportArchitecture = types.BoolValue(hasAttr(attrSet, "arch"))
	item.ReportHostname = types.BoolValue(hasAttr(attrSet, "hostName"))
	item.ReportKernelVersion = types.BoolValue(hasAttr(attrSet, "kernelVersion"))
	item.ReportMemorySize = types.BoolValue(hasAttr(attrSet, "memorySize"))
	item.ReportModelName = types.BoolValue(hasAttr(attrSet, "modelName"))
	item.ReportSerialNumber = types.BoolValue(hasAttr(attrSet, "serial"))
	item.ComplianceBaseline = types.BoolValue(hasAttr(attrSet, "insights"))
	item.ReportOSVersion = types.BoolValue(
		hasAttr(attrSet, "osMajor") || hasAttr(attrSet, "osMinor") || hasAttr(attrSet, "osPatch") || hasAttr(attrSet, "osString"),
	)
}
