// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
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

var _ datasource.DataSource = &PlansDataSource{}

func NewPlansDataSource() datasource.DataSource {
	return &PlansDataSource{}
}

// PlansDataSource lists all plans in Jamf Protect.
type PlansDataSource struct {
	client *client.Client
}

// PlansDataSourceModel maps the data source schema.
type PlansDataSourceModel struct {
	Plans []PlanDataSourceItemModel `tfsdk:"plans"`
}

// PlanDataSourceItemModel maps a single plan item (read-only, no timeouts).
type PlanDataSourceItemModel struct {
	ID                   types.String `tfsdk:"id"`
	Hash                 types.String `tfsdk:"hash"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	LogLevel             types.String `tfsdk:"log_level"`
	AutoUpdate           types.Bool   `tfsdk:"auto_update"`
	ActionConfigs        types.String `tfsdk:"action_configs"`
	ExceptionSets        types.List   `tfsdk:"exception_sets"`
	Telemetry            types.String `tfsdk:"telemetry"`
	TelemetryV2          types.String `tfsdk:"telemetry_v2"`
	USBControlSet        types.String `tfsdk:"usb_control_set"`
	AnalyticSets         types.List   `tfsdk:"analytic_sets"`
	CommsConfig          types.Object `tfsdk:"comms_config"`
	InfoSync             types.Object `tfsdk:"info_sync"`
	SignaturesFeedConfig types.Object `tfsdk:"signatures_feed_config"`
	Created              types.String `tfsdk:"created"`
	Updated              types.String `tfsdk:"updated"`
}

func (d *PlansDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plans"
}

func (d *PlansDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all plans in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"plans": schema.ListNestedAttribute{
				MarkdownDescription: "The list of plans.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: planDataSourceAttributes(),
				},
			},
		},
	}
}

func planDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the plan.",
			Computed:            true,
		},
		"hash": schema.StringAttribute{
			MarkdownDescription: "The configuration hash of the plan.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the plan.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the plan.",
			Computed:            true,
		},
		"log_level": schema.StringAttribute{
			MarkdownDescription: "The log level for the plan.",
			Computed:            true,
		},
		"auto_update": schema.BoolAttribute{
			MarkdownDescription: "Whether auto-updates are enabled for endpoints using this plan.",
			Computed:            true,
		},
		"action_configs": schema.StringAttribute{
			MarkdownDescription: "The ID of the action configuration associated with this plan.",
			Computed:            true,
		},
		"exception_sets": schema.ListAttribute{
			MarkdownDescription: "A list of exception set IDs associated with this plan.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"telemetry": schema.StringAttribute{
			MarkdownDescription: "The ID of the legacy telemetry configuration.",
			Computed:            true,
		},
		"telemetry_v2": schema.StringAttribute{
			MarkdownDescription: "The ID of the v2 telemetry configuration.",
			Computed:            true,
		},
		"usb_control_set": schema.StringAttribute{
			MarkdownDescription: "The ID of the USB control set associated with this plan.",
			Computed:            true,
		},
		"analytic_sets": schema.ListNestedAttribute{
			MarkdownDescription: "Analytic sets included in this plan.",
			Computed:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						MarkdownDescription: "The type of analytic set.",
						Computed:            true,
					},
					"analytic_set": schema.StringAttribute{
						MarkdownDescription: "The UUID of the analytic set.",
						Computed:            true,
					},
				},
			},
		},
		"comms_config": schema.SingleNestedAttribute{
			MarkdownDescription: "Communications configuration for the plan.",
			Computed:            true,
			Attributes: map[string]schema.Attribute{
				"fqdn": schema.StringAttribute{
					MarkdownDescription: "The fully qualified domain name for communications.",
					Computed:            true,
				},
				"protocol": schema.StringAttribute{
					MarkdownDescription: "The protocol to use.",
					Computed:            true,
				},
			},
		},
		"info_sync": schema.SingleNestedAttribute{
			MarkdownDescription: "Info sync configuration for the plan.",
			Computed:            true,
			Attributes: map[string]schema.Attribute{
				"attrs": schema.ListAttribute{
					MarkdownDescription: "A list of attribute names to sync.",
					Computed:            true,
					ElementType:         types.StringType,
				},
				"insights_sync_interval": schema.Int64Attribute{
					MarkdownDescription: "The interval in seconds for insights data synchronization.",
					Computed:            true,
				},
			},
		},
		"signatures_feed_config": schema.SingleNestedAttribute{
			MarkdownDescription: "Signatures feed configuration for the plan.",
			Computed:            true,
			Attributes: map[string]schema.Attribute{
				"mode": schema.StringAttribute{
					MarkdownDescription: "The signatures feed mode.",
					Computed:            true,
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

func (d *PlansDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *PlansDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PlansDataSourceModel

	var allPlans []planAPIModel
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "ASC",
			"field":     "NAME",
			"pageSize":  100,
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListPlans struct {
				Items    []planAPIModel  `json:"items"`
				PageInfo common.PageInfo `json:"pageInfo"`
			} `json:"listPlans"`
		}
		if err := d.client.Query(ctx, listPlansQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing plans", err.Error())
			return
		}

		allPlans = append(allPlans, result.ListPlans.Items...)

		if result.ListPlans.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListPlans.PageInfo.Next
	}

	tflog.Trace(ctx, "listed plans", map[string]any{"count": len(allPlans)})

	// Convert API models to data source models.
	plans := make([]PlanDataSourceItemModel, 0, len(allPlans))
	for _, api := range allPlans {
		item := planAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		plans = append(plans, item)
	}
	data.Plans = plans

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// planAPIToDataSourceItem maps a planAPIModel to PlanDataSourceItemModel.
func planAPIToDataSourceItem(api planAPIModel, _ *diag.Diagnostics) PlanDataSourceItemModel {
	item := PlanDataSourceItemModel{
		ID:         types.StringValue(api.ID),
		Hash:       types.StringValue(api.Hash),
		Name:       types.StringValue(api.Name),
		AutoUpdate: types.BoolValue(api.AutoUpdate),
		Created:    types.StringValue(api.Created),
		Updated:    types.StringValue(api.Updated),
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	if api.LogLevel != "" {
		item.LogLevel = types.StringValue(api.LogLevel)
	} else {
		item.LogLevel = types.StringNull()
	}

	// Action configs.
	if api.ActionConfigs != nil {
		item.ActionConfigs = types.StringValue(api.ActionConfigs.ID)
	} else {
		item.ActionConfigs = types.StringNull()
	}

	// Exception sets.
	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		item.ExceptionSets = common.StringsToList(uuids)
	} else {
		item.ExceptionSets = types.ListNull(types.StringType)
	}

	// Telemetry references.
	if api.Telemetry != nil && api.Telemetry.ID != "" {
		item.Telemetry = types.StringValue(api.Telemetry.ID)
	} else {
		item.Telemetry = types.StringNull()
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		item.TelemetryV2 = types.StringValue(api.TelemetryV2.ID)
	} else {
		item.TelemetryV2 = types.StringNull()
	}

	// USB control set.
	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		item.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		item.USBControlSet = types.StringNull()
	}

	// Analytic sets.
	analyticSetAttrTypes := map[string]attr.Type{
		"type":         types.StringType,
		"analytic_set": types.StringType,
	}
	if len(api.AnalyticSets) > 0 {
		var setVals []attr.Value
		for _, as := range api.AnalyticSets {
			setVals = append(setVals, types.ObjectValueMust(analyticSetAttrTypes, map[string]attr.Value{
				"type":         types.StringValue(as.Type),
				"analytic_set": types.StringValue(as.AnalyticSet.UUID),
			}))
		}
		item.AnalyticSets = types.ListValueMust(types.ObjectType{AttrTypes: analyticSetAttrTypes}, setVals)
	} else {
		item.AnalyticSets = types.ListNull(types.ObjectType{AttrTypes: analyticSetAttrTypes})
	}

	// Comms config.
	commsAttrTypes := map[string]attr.Type{
		"fqdn":     types.StringType,
		"protocol": types.StringType,
	}
	if api.CommsConfig != nil {
		item.CommsConfig = types.ObjectValueMust(commsAttrTypes, map[string]attr.Value{
			"fqdn":     types.StringValue(api.CommsConfig.FQDN),
			"protocol": types.StringValue(api.CommsConfig.Protocol),
		})
	} else {
		item.CommsConfig = types.ObjectNull(commsAttrTypes)
	}

	// Info sync.
	infoSyncAttrTypes := map[string]attr.Type{
		"attrs":                  types.ListType{ElemType: types.StringType},
		"insights_sync_interval": types.Int64Type,
	}
	if api.InfoSync != nil {
		item.InfoSync = types.ObjectValueMust(infoSyncAttrTypes, map[string]attr.Value{
			"attrs":                  common.StringsToList(api.InfoSync.Attrs),
			"insights_sync_interval": types.Int64Value(api.InfoSync.InsightsSyncInterval),
		})
	} else {
		item.InfoSync = types.ObjectNull(infoSyncAttrTypes)
	}

	// Signatures feed config.
	sigFeedAttrTypes := map[string]attr.Type{
		"mode": types.StringType,
	}
	if api.SignaturesFeedConfig != nil {
		item.SignaturesFeedConfig = types.ObjectValueMust(sigFeedAttrTypes, map[string]attr.Value{
			"mode": types.StringValue(api.SignaturesFeedConfig.Mode),
		})
	} else {
		item.SignaturesFeedConfig = types.ObjectNull(sigFeedAttrTypes)
	}

	return item
}
