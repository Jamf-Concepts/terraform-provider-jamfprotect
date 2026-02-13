// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &AnalyticSetsDataSource{}

func NewAnalyticSetsDataSource() datasource.DataSource {
	return &AnalyticSetsDataSource{}
}

// AnalyticSetsDataSource lists all analytic sets in Jamf Protect.
type AnalyticSetsDataSource struct {
	client *client.Client
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

func (d *AnalyticSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AnalyticSetsDataSourceModel

	// Fetch all analytic sets with pagination.
	var allItems []analyticSetAPIModel
	var nextToken *string

	for {
		vars := map[string]any{
			"RBAC_Plan":        true,
			"excludeAnalytics": false,
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListAnalyticSets struct {
				Items    []analyticSetAPIModel `json:"items"`
				PageInfo common.PageInfo       `json:"pageInfo"`
			} `json:"listAnalyticSets"`
		}
		if err := d.client.Query(ctx, listAnalyticSetsQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing analytic sets", err.Error())
			return
		}

		allItems = append(allItems, result.ListAnalyticSets.Items...)

		if result.ListAnalyticSets.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListAnalyticSets.PageInfo.Next
	}

	tflog.Trace(ctx, "listed analytic sets", map[string]any{"count": len(allItems)})

	analyticSets := make([]AnalyticSetDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := analyticSetAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		analyticSets = append(analyticSets, item)
	}
	data.AnalyticSets = analyticSets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// analyticSetAPIModel matches the client response structure.
type analyticSetAPIModel struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Analytics   []struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
		Jamf bool   `json:"jamf"`
	} `json:"analytics"`
	Plans []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"plans"`
	Created string   `json:"created"`
	Updated string   `json:"updated"`
	Managed bool     `json:"managed"`
	Types   []string `json:"types"`
}

// analyticSetAPIToDataSourceItem maps an analyticSetAPIModel to AnalyticSetDataSourceItemModel.
func analyticSetAPIToDataSourceItem(api analyticSetAPIModel, diags *diag.Diagnostics) AnalyticSetDataSourceItemModel {
	item := AnalyticSetDataSourceItemModel{
		UUID:    types.StringValue(api.UUID),
		Name:    types.StringValue(api.Name),
		Created: types.StringValue(api.Created),
		Updated: types.StringValue(api.Updated),
		Managed: types.BoolValue(api.Managed),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	item.Types = common.StringsToList(api.Types)

	// Analytics list.
	analyticAttrTypes := map[string]attr.Type{
		"uuid": types.StringType,
		"name": types.StringType,
		"jamf": types.BoolType,
	}
	var analyticVals []attr.Value
	for _, a := range api.Analytics {
		analyticVals = append(analyticVals, types.ObjectValueMust(analyticAttrTypes, map[string]attr.Value{
			"uuid": types.StringValue(a.UUID),
			"name": types.StringValue(a.Name),
			"jamf": types.BoolValue(a.Jamf),
		}))
	}
	if len(analyticVals) == 0 {
		item.Analytics = types.ListValueMust(types.ObjectType{AttrTypes: analyticAttrTypes}, []attr.Value{})
	} else {
		analyticList, d := types.ListValue(types.ObjectType{AttrTypes: analyticAttrTypes}, analyticVals)
		diags.Append(d...)
		item.Analytics = analyticList
	}

	// Plans list.
	planAttrTypes := map[string]attr.Type{
		"id":   types.StringType,
		"name": types.StringType,
	}
	var planVals []attr.Value
	for _, p := range api.Plans {
		planVals = append(planVals, types.ObjectValueMust(planAttrTypes, map[string]attr.Value{
			"id":   types.StringValue(p.ID),
			"name": types.StringValue(p.Name),
		}))
	}
	if len(planVals) == 0 {
		item.Plans = types.ListValueMust(types.ObjectType{AttrTypes: planAttrTypes}, []attr.Value{})
	} else {
		planList, d := types.ListValue(types.ObjectType{AttrTypes: planAttrTypes}, planVals)
		diags.Append(d...)
		item.Plans = planList
	}

	return item
}

const listAnalyticSetsQuery = `
query listAnalyticSets($nextToken: String, $direction: OrderDirection = DESC, $field: AnalyticSetOrderField = created, $RBAC_Plan: Boolean!, $excludeAnalytics: Boolean = false) {
  listAnalyticSets(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      uuid
      name
      description
      analytics @skip(if: $excludeAnalytics) {
        uuid
        name
        jamf
      }
      plans @include(if: $RBAC_Plan) {
        id
        name
      }
      created
      updated
      managed
      types
    }
    pageInfo {
      next
      total
    }
  }
}
`
