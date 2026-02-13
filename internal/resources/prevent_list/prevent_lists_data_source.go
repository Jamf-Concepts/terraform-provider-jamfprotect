// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package preventlist

import (
	"context"
	"fmt"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &PreventListsDataSource{}

func NewPreventListsDataSource() datasource.DataSource {
	return &PreventListsDataSource{}
}

// PreventListsDataSource lists all prevent lists in Jamf Protect.
type PreventListsDataSource struct {
	client *client.Client
}

// PreventListsDataSourceModel maps the data source schema.
type PreventListsDataSourceModel struct {
	PreventLists []PreventListDataSourceItemModel `tfsdk:"prevent_lists"`
}

// PreventListDataSourceItemModel maps a single prevent list item (read-only, no timeouts).
type PreventListDataSourceItemModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	EntryCount  types.Int64  `tfsdk:"entry_count"`
	List        types.List   `tfsdk:"list"`
	Created     types.String `tfsdk:"created"`
}

func (d *PreventListsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prevent_lists"
}

func (d *PreventListsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all prevent lists in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"prevent_lists": schema.ListNestedAttribute{
				MarkdownDescription: "The list of prevent lists.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the prevent list.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the prevent list.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the prevent list.",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of prevent list.",
							Computed:            true,
						},
						"entry_count": schema.Int64Attribute{
							MarkdownDescription: "The number of entries in the list.",
							Computed:            true,
						},
						"list": schema.ListAttribute{
							MarkdownDescription: "The entries in the prevent list.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"created": schema.StringAttribute{
							MarkdownDescription: "The creation timestamp.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *PreventListsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *PreventListsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PreventListsDataSourceModel

	var allItems []preventListAPIModel
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
			ListPreventLists struct {
				Items    []preventListAPIModel `json:"items"`
				PageInfo common.PageInfo       `json:"pageInfo"`
			} `json:"listPreventLists"`
		}
		if err := d.client.Query(ctx, listPreventListsQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing prevent lists", err.Error())
			return
		}

		allItems = append(allItems, result.ListPreventLists.Items...)

		if result.ListPreventLists.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListPreventLists.PageInfo.Next
	}

	tflog.Trace(ctx, "listed prevent lists", map[string]any{"count": len(allItems)})

	items := make([]PreventListDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := PreventListDataSourceItemModel{
			ID:         types.StringValue(api.ID),
			Name:       types.StringValue(api.Name),
			Type:       types.StringValue(api.Type),
			EntryCount: types.Int64Value(api.Count),
			List:       common.StringsToList(api.List),
			Created:    types.StringValue(api.Created),
		}
		if api.Description != "" {
			item.Description = types.StringValue(api.Description)
		} else {
			item.Description = types.StringNull()
		}
		items = append(items, item)
	}
	data.PreventLists = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
