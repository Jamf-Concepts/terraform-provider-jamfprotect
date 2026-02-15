// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &TelemetriesV2DataSource{}

func NewTelemetriesV2DataSource() datasource.DataSource {
	return &TelemetriesV2DataSource{}
}

// TelemetriesV2DataSource lists all v2 telemetry configurations in Jamf Protect.
type TelemetriesV2DataSource struct {
	service *jamfprotect.Service
}

// TelemetriesV2DataSourceModel maps the data source schema.
type TelemetriesV2DataSourceModel struct {
	TelemetriesV2 []TelemetryV2DataSourceItemModel `tfsdk:"telemetries`
}

// TelemetryV2DataSourceItemModel maps a single v2 telemetry item (read-only, no timeouts).
type TelemetryV2DataSourceItemModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	LogFilePath         types.List   `tfsdk:"log_file_path"`
	DiagnosticReports   types.Bool   `tfsdk:"collect_diagnostic_and_crash_reports"`
	PerformanceMetrics  types.Bool   `tfsdk:"collect_performance_metrics"`
	FileHashes          types.Bool   `tfsdk:"file_hashes"`
	LogAppsProcesses    types.Bool   `tfsdk:"log_applications_and_processes"`
	LogAccessAuth       types.Bool   `tfsdk:"log_access_and_authentication"`
	LogUsersGroups      types.Bool   `tfsdk:"log_users_and_groups"`
	LogPersistence      types.Bool   `tfsdk:"log_persistence"`
	LogHardwareSoftware types.Bool   `tfsdk:"log_hardware_and_software"`
	LogAppleSecurity    types.Bool   `tfsdk:"log_apple_security"`
	LogSystem           types.Bool   `tfsdk:"log_system"`
	Created             types.String `tfsdk:"created"`
	Updated             types.String `tfsdk:"updated"`
}

func (d *TelemetriesV2DataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_telemetries"
}

func (d *TelemetriesV2DataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all v2 telemetry configurations in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"telemetries": schema.ListNestedAttribute{
				MarkdownDescription: "The list of v2 telemetry configurations.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the telemetry configuration.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the telemetry configuration.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the telemetry configuration.",
							Computed:            true,
						},
						"log_file_path": schema.ListAttribute{
							MarkdownDescription: "Log file paths to collect.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"collect_diagnostic_and_crash_reports": schema.BoolAttribute{
							MarkdownDescription: "Whether diagnostic and crash report collection is enabled.",
							Computed:            true,
						},
						"collect_performance_metrics": schema.BoolAttribute{
							MarkdownDescription: "Whether performance metrics collection is enabled.",
							Computed:            true,
						},
						"file_hashes": schema.BoolAttribute{
							MarkdownDescription: "Whether file hashing is enabled.",
							Computed:            true,
						},
						"log_applications_and_processes": schema.BoolAttribute{
							MarkdownDescription: "Collect application and process events.",
							Computed:            true,
						},
						"log_access_and_authentication": schema.BoolAttribute{
							MarkdownDescription: "Collect access and authentication events.",
							Computed:            true,
						},
						"log_users_and_groups": schema.BoolAttribute{
							MarkdownDescription: "Collect user and group management events.",
							Computed:            true,
						},
						"log_persistence": schema.BoolAttribute{
							MarkdownDescription: "Collect persistence-related events.",
							Computed:            true,
						},
						"log_hardware_and_software": schema.BoolAttribute{
							MarkdownDescription: "Collect hardware and software events.",
							Computed:            true,
						},
						"log_apple_security": schema.BoolAttribute{
							MarkdownDescription: "Collect Apple security events.",
							Computed:            true,
						},
						"log_system": schema.BoolAttribute{
							MarkdownDescription: "Collect system events.",
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
					},
				},
			},
		},
	}
}

func (d *TelemetriesV2DataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *TelemetriesV2DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TelemetriesV2DataSourceModel

	allItems, err := d.service.ListTelemetriesV2(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing v2 telemetries", err.Error())
		return
	}

	tflog.Trace(ctx, "listed v2 telemetries", map[string]any{"count": len(allItems)})

	items := make([]TelemetryV2DataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		flags := flagsFromEvents(api.Events)
		item := TelemetryV2DataSourceItemModel{
			ID:                  types.StringValue(api.ID),
			Name:                types.StringValue(api.Name),
			DiagnosticReports:   types.BoolValue(api.LogFileCollection),
			PerformanceMetrics:  types.BoolValue(api.PerformanceMetrics),
			FileHashes:          types.BoolValue(api.FileHashing),
			Created:             types.StringValue(api.Created),
			Updated:             types.StringValue(api.Updated),
			LogFilePath:         common.StringsToList(api.LogFiles),
			LogAppsProcesses:    types.BoolValue(flags.LogAppsProcesses),
			LogAccessAuth:       types.BoolValue(flags.LogAccessAuth),
			LogUsersGroups:      types.BoolValue(flags.LogUsersGroups),
			LogPersistence:      types.BoolValue(flags.LogPersistence),
			LogHardwareSoftware: types.BoolValue(flags.LogHardwareSoftware),
			LogAppleSecurity:    types.BoolValue(flags.LogAppleSecurity),
			LogSystem:           types.BoolValue(flags.LogSystem),
		}
		if api.Description != "" {
			item.Description = types.StringValue(api.Description)
		} else {
			item.Description = types.StringNull()
		}
		items = append(items, item)
	}
	data.TelemetriesV2 = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
