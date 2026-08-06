// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

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

var _ datasource.DataSource = &UnifiedLoggingFilterSetsDataSource{}

// NewUnifiedLoggingFilterSetsDataSource instantiates the unified logging filter sets data source.
func NewUnifiedLoggingFilterSetsDataSource() datasource.DataSource {
	return &UnifiedLoggingFilterSetsDataSource{}
}

// UnifiedLoggingFilterSetsDataSource lists all unified logging filter sets in Jamf Protect.
type UnifiedLoggingFilterSetsDataSource struct {
	client *jamfprotect.Client
}

// UnifiedLoggingFilterSetsDataSourceModel maps the data source schema.
type UnifiedLoggingFilterSetsDataSourceModel struct {
	UnifiedLoggingFilterSets []UnifiedLoggingFilterSetDataSourceItemModel `tfsdk:"unified_logging_filter_sets"`
}

// UnifiedLoggingFilterSetDataSourceItemModel maps a single unified logging filter set item.
type UnifiedLoggingFilterSetDataSourceItemModel struct {
	UUID        types.String `tfsdk:"uuid"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Filters     types.List   `tfsdk:"filters"`
	Plans       types.List   `tfsdk:"plans"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
}

// Metadata returns the unified logging filter sets data source type name.
func (d *UnifiedLoggingFilterSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter_sets"
}

// Schema defines the unified logging filter sets data source schema.
func (d *UnifiedLoggingFilterSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all unified logging filter sets in Jamf Protect. Filter sets group unified logging filters and scope them to plans.",
		Attributes: map[string]schema.Attribute{
			"unified_logging_filter_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of unified logging filter sets, sorted by name.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: filterSetDataSourceAttributes(),
				},
			},
		},
	}
}

// filterSetDataSourceAttributes returns the per-item data source attributes.
func filterSetDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"uuid": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the unified logging filter set.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the unified logging filter set.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the unified logging filter set.",
			Computed:            true,
		},
		"filters": schema.ListNestedAttribute{
			MarkdownDescription: "Unified logging filters included in this filter set.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"uuid": schema.StringAttribute{
						MarkdownDescription: "The unified logging filter UUID.",
						Computed:            true,
					},
					"name": schema.StringAttribute{
						MarkdownDescription: "The unified logging filter name.",
						Computed:            true,
					},
				},
			},
		},
		"plans": schema.ListNestedAttribute{
			MarkdownDescription: "Plans that this filter set is assigned to.",
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
func (d *UnifiedLoggingFilterSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// Read lists unified logging filter sets into state.
func (d *UnifiedLoggingFilterSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data UnifiedLoggingFilterSetsDataSourceModel

	items, err := d.client.ListUnifiedLoggingFilterSets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing unified logging filter sets", err.Error())
		return
	}

	tflog.Trace(ctx, "listed unified logging filter sets", map[string]any{"count": len(items)})

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	filterSets := make([]UnifiedLoggingFilterSetDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := filterSetAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		filterSets = append(filterSets, item)
	}
	data.UnifiedLoggingFilterSets = filterSets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
