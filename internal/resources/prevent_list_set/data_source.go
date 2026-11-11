// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ datasource.DataSource = &PreventListSetsDataSource{}

// NewPreventListSetsDataSource instantiates the prevent list sets data source.
func NewPreventListSetsDataSource() datasource.DataSource {
	return &PreventListSetsDataSource{}
}

// PreventListSetsDataSource lists all prevent list sets in Jamf Protect.
type PreventListSetsDataSource struct {
	client *jamfprotect.Client
}

// PreventListSetsDataSourceModel maps the data source schema.
type PreventListSetsDataSourceModel struct {
	PreventListSets []PreventListSetDataSourceItemModel `tfsdk:"prevent_list_sets"`
}

// PreventListSetDataSourceItemModel maps a single prevent list set item.
type PreventListSetDataSourceItemModel struct {
	UUID         types.String `tfsdk:"uuid"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	PreventLists types.List   `tfsdk:"prevent_lists"`
	Plans        types.List   `tfsdk:"plans"`
	Created      types.String `tfsdk:"created"`
	Updated      types.String `tfsdk:"updated"`
}

// Metadata returns the prevent list sets data source type name.
func (d *PreventListSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prevent_list_sets"
}

// Schema defines the prevent list sets data source schema.
func (d *PreventListSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all prevent list sets in Jamf Protect. Prevent list sets group custom prevent lists and scope them to plans.",
		Attributes: map[string]schema.Attribute{
			"prevent_list_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of prevent list sets, sorted by name.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: preventListSetDataSourceAttributes(),
				},
			},
		},
	}
}

// preventListSetDataSourceAttributes returns the per-item data source attributes.
func preventListSetDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"uuid": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the prevent list set.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the prevent list set.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the prevent list set.",
			Computed:            true,
		},
		"prevent_lists": schema.ListNestedAttribute{
			MarkdownDescription: "Custom prevent lists included in this prevent list set.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{
						MarkdownDescription: "The custom prevent list ID.",
						Computed:            true,
					},
					"name": schema.StringAttribute{
						MarkdownDescription: "The custom prevent list name.",
						Computed:            true,
					},
				},
			},
		},
		"plans": schema.ListNestedAttribute{
			MarkdownDescription: "Plans that this prevent list set is assigned to.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{
						MarkdownDescription: "The plan ID.",
						Computed:            true,
					},
					"name": schema.StringAttribute{
						MarkdownDescription: "The plan name.",
						Computed:            true,
					},
				},
			},
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

// Configure assigns the Jamf Protect client for data source reads.
func (d *PreventListSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// Read lists prevent list sets into state.
func (d *PreventListSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PreventListSetsDataSourceModel

	items, err := d.client.ListPreventListSets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing prevent list sets", err.Error())
		return
	}

	tflog.Trace(ctx, "listed prevent list sets", map[string]any{"count": len(items)})

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	preventListSets := make([]PreventListSetDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := preventListSetAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		preventListSets = append(preventListSets, item)
	}
	data.PreventListSets = preventListSets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
