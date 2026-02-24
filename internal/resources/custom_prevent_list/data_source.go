// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &CustomPreventListsDataSource{}

func NewCustomPreventListsDataSource() datasource.DataSource {
	return &CustomPreventListsDataSource{}
}

// CustomPreventListsDataSource lists all custom prevent lists in Jamf Protect.
type CustomPreventListsDataSource struct {
	service *jamfprotect.Service
}

// CustomPreventListsDataSourceModel maps the data source schema.
type CustomPreventListsDataSourceModel struct {
	CustomPreventLists []CustomPreventListDataSourceItemModel `tfsdk:"custom_prevent_lists"`
}

// CustomPreventListDataSourceItemModel maps a single prevent list item (read-only, no timeouts).
type CustomPreventListDataSourceItemModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	PreventType types.String `tfsdk:"prevent_type"`
	EntryCount  types.Int64  `tfsdk:"entry_count"`
	ListData    types.List   `tfsdk:"list_data"`
	Created     types.String `tfsdk:"created"`
}

func (d *CustomPreventListsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_prevent_lists"
}

func (d *CustomPreventListsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all custom prevent lists in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"custom_prevent_lists": schema.ListNestedAttribute{
				MarkdownDescription: "The list of custom prevent lists.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the custom prevent list.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the custom prevent list.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the custom prevent list.",
							Computed:            true,
						},
						"prevent_type": schema.StringAttribute{
							MarkdownDescription: "The type of custom prevent list.",
							Computed:            true,
						},
						"entry_count": schema.Int64Attribute{
							MarkdownDescription: "The number of entries in the custom prevent list.",
							Computed:            true,
						},
						"list_data": schema.ListAttribute{
							MarkdownDescription: "The entries in the custom prevent list.",
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

func (d *CustomPreventListsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *CustomPreventListsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CustomPreventListsDataSourceModel

	allItems, err := d.service.ListCustomPreventLists(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing prevent lists", err.Error())
		return
	}

	tflog.Trace(ctx, "listed prevent lists", map[string]any{"count": len(allItems)})

	items := make([]CustomPreventListDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := customPreventListAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		items = append(items, item)
	}
	data.CustomPreventLists = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
