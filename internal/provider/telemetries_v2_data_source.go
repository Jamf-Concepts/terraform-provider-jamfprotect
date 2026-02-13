// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &TelemetriesV2DataSource{}

func NewTelemetriesV2DataSource() datasource.DataSource {
	return &TelemetriesV2DataSource{}
}

// TelemetriesV2DataSource lists all v2 telemetry configurations in Jamf Protect.
type TelemetriesV2DataSource struct {
	client *client.Client
}

// TelemetriesV2DataSourceModel maps the data source schema.
type TelemetriesV2DataSourceModel struct {
	TelemetriesV2 []TelemetryV2DataSourceItemModel `tfsdk:"telemetries_v2"`
}

// TelemetryV2DataSourceItemModel maps a single v2 telemetry item (read-only, no timeouts).
type TelemetryV2DataSourceItemModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	LogFiles           types.List   `tfsdk:"log_files"`
	LogFileCollection  types.Bool   `tfsdk:"log_file_collection"`
	PerformanceMetrics types.Bool   `tfsdk:"performance_metrics"`
	Events             types.List   `tfsdk:"events"`
	FileHashing        types.Bool   `tfsdk:"file_hashing"`
	Created            types.String `tfsdk:"created"`
	Updated            types.String `tfsdk:"updated"`
}

func (d *TelemetriesV2DataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_telemetries_v2"
}

func (d *TelemetriesV2DataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all v2 telemetry configurations in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"telemetries_v2": schema.ListNestedAttribute{
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
						"log_files": schema.ListAttribute{
							MarkdownDescription: "Log file paths to collect.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"log_file_collection": schema.BoolAttribute{
							MarkdownDescription: "Whether log file collection is enabled.",
							Computed:            true,
						},
						"performance_metrics": schema.BoolAttribute{
							MarkdownDescription: "Whether performance metrics collection is enabled.",
							Computed:            true,
						},
						"events": schema.ListAttribute{
							MarkdownDescription: "Endpoint Security events to monitor.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"file_hashing": schema.BoolAttribute{
							MarkdownDescription: "Whether file hashing is enabled.",
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
	d.client = client
}

func (d *TelemetriesV2DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TelemetriesV2DataSourceModel

	var allItems []telemetryV2APIModel
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "ASC",
			"field":     "NAME",
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListTelemetriesV2 struct {
				Items    []telemetryV2APIModel `json:"items"`
				PageInfo pageInfo              `json:"pageInfo"`
			} `json:"listTelemetriesV2"`
		}
		if err := d.client.Query(ctx, listTelemetriesV2Query, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing v2 telemetries", err.Error())
			return
		}

		allItems = append(allItems, result.ListTelemetriesV2.Items...)

		if result.ListTelemetriesV2.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListTelemetriesV2.PageInfo.Next
	}

	tflog.Trace(ctx, "listed v2 telemetries", map[string]any{"count": len(allItems)})

	items := make([]TelemetryV2DataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := TelemetryV2DataSourceItemModel{
			ID:                 types.StringValue(api.ID),
			Name:               types.StringValue(api.Name),
			LogFileCollection:  types.BoolValue(api.LogFileCollection),
			PerformanceMetrics: types.BoolValue(api.PerformanceMetrics),
			FileHashing:        types.BoolValue(api.FileHashing),
			Created:            types.StringValue(api.Created),
			Updated:            types.StringValue(api.Updated),
			LogFiles:           stringsToList(api.LogFiles),
			Events:             stringsToList(api.Events),
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
