// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &AnalyticSetsDataSource{}

func NewAnalyticSetsDataSource() datasource.DataSource {
	return &AnalyticSetsDataSource{}
}

// AnalyticSetsDataSource lists all analytic sets in Jamf Protect.
type AnalyticSetsDataSource struct {
	service *jamfprotect.Service
}

// AnalyticSetsDataSourceModel maps the data source schema.
type AnalyticSetsDataSourceModel struct {
	AnalyticSets []AnalyticSetDataSourceItemModel `tfsdk:"analytic_sets"`
}

// AnalyticSetDataSourceItemModel maps a single analytic set item.
type AnalyticSetDataSourceItemModel struct {
	UUID        types.String `tfsdk:"uuid"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Analytics   types.List   `tfsdk:"analytics"`
	Plans       types.List   `tfsdk:"plans"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
	Managed     types.Bool   `tfsdk:"managed"`
	Types       types.List   `tfsdk:"types"`
}

func (d *AnalyticSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytic_sets"
}

func (d *AnalyticSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all analytic sets in Jamf Protect. Analytic sets are collections of analytics that can be associated with plans.",
		Attributes: map[string]schema.Attribute{
			"analytic_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of analytic sets.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: analyticSetDataSourceAttributes(),
				},
			},
		},
	}
}

func analyticSetDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"uuid": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the analytic set.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the analytic set.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the analytic set.",
			Computed:            true,
		},
		"analytics": schema.ListNestedAttribute{
			MarkdownDescription: "Analytics included in this set.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"uuid": schema.StringAttribute{
						MarkdownDescription: "The analytic UUID.",
						Computed:            true,
					},
					"name": schema.StringAttribute{
						MarkdownDescription: "The analytic name.",
						Computed:            true,
					},
					"jamf": schema.BoolAttribute{
						MarkdownDescription: "Whether this is a Jamf-managed analytic.",
						Computed:            true,
					},
				},
			},
		},
		"plans": schema.ListNestedAttribute{
			MarkdownDescription: "Plans that use this analytic set.",
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
		"managed": schema.BoolAttribute{
			MarkdownDescription: "Whether this is a Jamf-managed analytic set.",
			Computed:            true,
		},
		"types": schema.ListAttribute{
			MarkdownDescription: "The types of analytics in this set.",
			Computed:            true,
			ElementType:         types.StringType,
		},
	}
}

func (d *AnalyticSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *AnalyticSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AnalyticSetsDataSourceModel

	items, err := d.service.ListAnalyticSets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing analytic sets", err.Error())
		return
	}

	tflog.Trace(ctx, "listed analytic sets", map[string]any{"count": len(items)})

	analyticSets := make([]AnalyticSetDataSourceItemModel, 0, len(items))
	for _, api := range items {
		if isSystemAnalyticSetName(api.Name) {
			continue
		}
		item := analyticSetAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		analyticSets = append(analyticSets, item)
	}
	data.AnalyticSets = analyticSets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// analyticSetAPIToDataSourceItem is defined in state_builders.go.
