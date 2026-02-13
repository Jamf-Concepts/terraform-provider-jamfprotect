// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &AnalyticsDataSource{}

func NewAnalyticsDataSource() datasource.DataSource {
	return &AnalyticsDataSource{}
}

// AnalyticsDataSource lists all analytics in Jamf Protect.
type AnalyticsDataSource struct {
	client *client.Client
}

// AnalyticsDataSourceModel maps the data source schema.
type AnalyticsDataSourceModel struct {
	Analytics []AnalyticDataSourceItemModel `tfsdk:"analytics"`
}

// AnalyticDataSourceItemModel maps a single analytic item (read-only, no timeouts).
type AnalyticDataSourceItemModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	InputType       types.String `tfsdk:"input_type"`
	Description     types.String `tfsdk:"description"`
	Filter          types.String `tfsdk:"filter"`
	Level           types.Int64  `tfsdk:"level"`
	Severity        types.String `tfsdk:"severity"`
	Tags            types.List   `tfsdk:"tags"`
	Categories      types.List   `tfsdk:"categories"`
	SnapshotFiles   types.List   `tfsdk:"snapshot_files"`
	Actions         types.List   `tfsdk:"actions"`
	AnalyticActions types.List   `tfsdk:"analytic_actions"`
	Context         types.List   `tfsdk:"context"`
	Created         types.String `tfsdk:"created"`
	Updated         types.String `tfsdk:"updated"`
}

func (d *AnalyticsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytics"
}

func (d *AnalyticsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all analytics in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"analytics": schema.ListNestedAttribute{
				MarkdownDescription: "The list of analytics.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: analyticDataSourceAttributes(),
				},
			},
		},
	}
}

func analyticDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the analytic.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the analytic.",
			Computed:            true,
		},
		"input_type": schema.StringAttribute{
			MarkdownDescription: "The input type for the analytic.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the analytic.",
			Computed:            true,
		},
		"filter": schema.StringAttribute{
			MarkdownDescription: "The predicate filter expression.",
			Computed:            true,
		},
		"level": schema.Int64Attribute{
			MarkdownDescription: "The alert level.",
			Computed:            true,
		},
		"severity": schema.StringAttribute{
			MarkdownDescription: "The severity level.",
			Computed:            true,
		},
		"tags": schema.ListAttribute{
			MarkdownDescription: "Tags associated with the analytic.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"categories": schema.ListAttribute{
			MarkdownDescription: "Categories associated with the analytic.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"snapshot_files": schema.ListAttribute{
			MarkdownDescription: "Snapshot file paths to capture.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"actions": schema.ListAttribute{
			MarkdownDescription: "Legacy actions associated with the analytic.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"analytic_actions": schema.ListNestedAttribute{
			MarkdownDescription: "Actions to perform when the analytic triggers.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						MarkdownDescription: "The action name.",
						Computed:            true,
					},
					"parameters": schema.MapAttribute{
						MarkdownDescription: "Key-value parameters for the action.",
						Computed:            true,
						ElementType:         types.StringType,
					},
				},
			},
		},
		"context": schema.ListNestedAttribute{
			MarkdownDescription: "Context entries for the analytic.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						MarkdownDescription: "The context entry name.",
						Computed:            true,
					},
					"type": schema.StringAttribute{
						MarkdownDescription: "The context entry type.",
						Computed:            true,
					},
					"exprs": schema.ListAttribute{
						MarkdownDescription: "Expressions for the context entry.",
						Computed:            true,
						ElementType:         types.StringType,
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

func (d *AnalyticsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AnalyticsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AnalyticsDataSourceModel

	var result struct {
		ListAnalytics struct {
			Items    []analyticAPIModel `json:"items"`
			PageInfo common.PageInfo    `json:"pageInfo"`
		} `json:"listAnalytics"`
	}
	if err := d.client.Query(ctx, listAnalyticsQuery, nil, &result); err != nil {
		resp.Diagnostics.AddError("Error listing analytics", err.Error())
		return
	}

	tflog.Trace(ctx, "listed analytics", map[string]any{"count": len(result.ListAnalytics.Items)})

	analytics := make([]AnalyticDataSourceItemModel, 0, len(result.ListAnalytics.Items))
	for _, api := range result.ListAnalytics.Items {
		item := analyticAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		analytics = append(analytics, item)
	}
	data.Analytics = analytics

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// analyticAPIToDataSourceItem maps an analyticAPIModel to AnalyticDataSourceItemModel.
func analyticAPIToDataSourceItem(api analyticAPIModel, diags *diag.Diagnostics) AnalyticDataSourceItemModel {
	item := AnalyticDataSourceItemModel{
		ID:        types.StringValue(api.UUID),
		Name:      types.StringValue(api.Name),
		InputType: types.StringValue(api.InputType),
		Filter:    types.StringValue(api.Filter),
		Level:     types.Int64Value(api.Level),
		Severity:  types.StringValue(api.Severity),
		Created:   types.StringValue(api.Created),
		Updated:   types.StringValue(api.Updated),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	item.Tags = common.StringsToList(api.Tags)
	item.Categories = common.StringsToList(api.Categories)
	item.SnapshotFiles = common.StringsToList(api.SnapshotFiles)

	if len(api.Actions) == 0 {
		item.Actions = types.ListNull(types.StringType)
	} else {
		item.Actions = common.StringsToList(api.Actions)
	}

	// Analytic actions.
	actionAttrTypes := map[string]attr.Type{
		"name":       types.StringType,
		"parameters": types.MapType{ElemType: types.StringType},
	}
	var actionVals []attr.Value
	for _, a := range api.AnalyticActions {
		paramVal := types.MapNull(types.StringType)
		if a.Parameters != "" && a.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(a.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", a.Parameters, err.Error()))
				return item
			}
			if len(paramMap) > 0 {
				paramElements := make(map[string]attr.Value, len(paramMap))
				for k, v := range paramMap {
					paramElements[k] = types.StringValue(v)
				}
				mapVal, d := types.MapValue(types.StringType, paramElements)
				diags.Append(d...)
				paramVal = mapVal
			}
		}
		actionVals = append(actionVals, types.ObjectValueMust(actionAttrTypes, map[string]attr.Value{
			"name":       types.StringValue(a.Name),
			"parameters": paramVal,
		}))
	}
	if len(actionVals) == 0 {
		item.AnalyticActions = types.ListValueMust(types.ObjectType{AttrTypes: actionAttrTypes}, []attr.Value{})
	} else {
		actionList, d := types.ListValue(types.ObjectType{AttrTypes: actionAttrTypes}, actionVals)
		diags.Append(d...)
		item.AnalyticActions = actionList
	}

	// Context.
	ctxAttrTypes := map[string]attr.Type{
		"name":  types.StringType,
		"type":  types.StringType,
		"exprs": types.ListType{ElemType: types.StringType},
	}
	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(ctxAttrTypes, map[string]attr.Value{
			"name":  types.StringValue(c.Name),
			"type":  types.StringValue(c.Type),
			"exprs": common.StringsToList(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		item.Context = types.ListValueMust(types.ObjectType{AttrTypes: ctxAttrTypes}, []attr.Value{})
	} else {
		ctxList, d := types.ListValue(types.ObjectType{AttrTypes: ctxAttrTypes}, ctxVals)
		diags.Append(d...)
		item.Context = ctxList
	}

	return item
}
