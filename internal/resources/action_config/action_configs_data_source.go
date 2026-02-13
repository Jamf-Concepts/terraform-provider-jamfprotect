// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package actionconfig

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

var _ datasource.DataSource = &ActionConfigsDataSource{}

func NewActionConfigsDataSource() datasource.DataSource {
	return &ActionConfigsDataSource{}
}

// ActionConfigsDataSource lists all action configurations in Jamf Protect.
type ActionConfigsDataSource struct {
	client *client.Client
}

// ActionConfigsDataSourceModel maps the data source schema.
type ActionConfigsDataSourceModel struct {
	ActionConfigs []ActionConfigDataSourceItemModel `tfsdk:"action_configs"`
}

// ActionConfigDataSourceItemModel maps a single action config item.
// Note: The list query only returns basic fields (id, name, description, created, updated).
// Full alertConfig details require the individual getActionConfigs query.
type ActionConfigDataSourceItemModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
}

func (d *ActionConfigsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_action_configs"
}

func (d *ActionConfigsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all action configurations in Jamf Protect. Note: only basic fields are returned by the list API; use the `jamfprotect_action_config` resource to read full details including `alert_config`.",
		Attributes: map[string]schema.Attribute{
			"action_configs": schema.ListNestedAttribute{
				MarkdownDescription: "The list of action configurations.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the action configuration.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the action configuration.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the action configuration.",
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

func (d *ActionConfigsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// actionConfigListItemAPIModel represents the limited fields returned by listActionConfigs.
type actionConfigListItemAPIModel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
}

func (d *ActionConfigsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ActionConfigsDataSourceModel

	var allItems []actionConfigListItemAPIModel
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
			ListActionConfigs struct {
				Items    []actionConfigListItemAPIModel `json:"items"`
				PageInfo common.PageInfo                `json:"pageInfo"`
			} `json:"listActionConfigs"`
		}
		if err := d.client.Query(ctx, listActionConfigsQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing action configs", err.Error())
			return
		}

		allItems = append(allItems, result.ListActionConfigs.Items...)

		if result.ListActionConfigs.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListActionConfigs.PageInfo.Next
	}

	tflog.Trace(ctx, "listed action configs", map[string]any{"count": len(allItems)})

	items := make([]ActionConfigDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := ActionConfigDataSourceItemModel{
			ID:      types.StringValue(api.ID),
			Name:    types.StringValue(api.Name),
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
	data.ActionConfigs = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
