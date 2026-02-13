// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &UnifiedLoggingFiltersDataSource{}

func NewUnifiedLoggingFiltersDataSource() datasource.DataSource {
	return &UnifiedLoggingFiltersDataSource{}
}

// UnifiedLoggingFiltersDataSource lists all unified logging filters in Jamf Protect.
type UnifiedLoggingFiltersDataSource struct {
	client *client.Client
}

// UnifiedLoggingFiltersDataSourceModel maps the data source schema.
type UnifiedLoggingFiltersDataSourceModel struct {
	UnifiedLoggingFilters []UnifiedLoggingFilterDataSourceItemModel `tfsdk:"unified_logging_filters"`
}

// UnifiedLoggingFilterDataSourceItemModel maps a single unified logging filter item.
type UnifiedLoggingFilterDataSourceItemModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Filter      types.String `tfsdk:"filter"`
	Level       types.String `tfsdk:"level"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Tags        types.List   `tfsdk:"tags"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
}

func (d *UnifiedLoggingFiltersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filters"
}

func (d *UnifiedLoggingFiltersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all unified logging filters in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"unified_logging_filters": schema.ListNestedAttribute{
				MarkdownDescription: "The list of unified logging filters.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the unified logging filter.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the unified logging filter.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the unified logging filter.",
							Computed:            true,
						},
						"filter": schema.StringAttribute{
							MarkdownDescription: "The predicate filter expression.",
							Computed:            true,
						},
						"level": schema.StringAttribute{
							MarkdownDescription: "The unified logging level.",
							Computed:            true,
						},
						"enabled": schema.BoolAttribute{
							MarkdownDescription: "Whether the filter is enabled.",
							Computed:            true,
						},
						"tags": schema.ListAttribute{
							MarkdownDescription: "Tags associated with the filter.",
							Computed:            true,
							ElementType:         types.StringType,
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

func (d *UnifiedLoggingFiltersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *UnifiedLoggingFiltersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data UnifiedLoggingFiltersDataSourceModel

	var allItems []unifiedLoggingFilterAPIModel
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "ASC",
			"field":     "NAME",
			"filter":    map[string]any{},
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListUnifiedLoggingFilters struct {
				Items    []unifiedLoggingFilterAPIModel `json:"items"`
				PageInfo common.PageInfo                `json:"pageInfo"`
			} `json:"listUnifiedLoggingFilters"`
		}
		if err := d.client.Query(ctx, listUnifiedLoggingFiltersQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing unified logging filters", err.Error())
			return
		}

		allItems = append(allItems, result.ListUnifiedLoggingFilters.Items...)

		if result.ListUnifiedLoggingFilters.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListUnifiedLoggingFilters.PageInfo.Next
	}

	tflog.Trace(ctx, "listed unified logging filters", map[string]any{"count": len(allItems)})

	items := make([]UnifiedLoggingFilterDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := UnifiedLoggingFilterDataSourceItemModel{
			ID:      types.StringValue(api.UUID),
			Name:    types.StringValue(api.Name),
			Filter:  types.StringValue(api.Filter),
			Level:   types.StringValue(api.Level),
			Enabled: types.BoolValue(api.Enabled),
			Tags:    common.StringsToList(api.Tags),
			Created: types.StringValue(api.Created),
			Updated: types.StringValue(api.Updated),
		}
		if api.Description != "" {
			item.Description = types.StringValue(api.Description)
		} else {
			item.Description = types.StringNull()
		}
		items = append(items, item)
	}
	data.UnifiedLoggingFilters = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
