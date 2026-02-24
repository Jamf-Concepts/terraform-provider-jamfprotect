package analytic

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &AnalyticsDataSource{}

func NewAnalyticsDataSource() datasource.DataSource {
	return &AnalyticsDataSource{}
}

// AnalyticsDataSource lists all analytics in Jamf Protect.
type AnalyticsDataSource struct {
	service *jamfprotect.Service
}

// AnalyticsDataSourceModel maps the data source schema.
type AnalyticsDataSourceModel struct {
	Analytics []AnalyticDataSourceItemModel `tfsdk:"analytics"`
}

// AnalyticDataSourceItemModel maps a single analytic item (read-only, no timeouts).
type AnalyticDataSourceItemModel struct {
	ID                          types.String `tfsdk:"id"`
	Name                        types.String `tfsdk:"name"`
	SensorType                  types.String `tfsdk:"sensor_type"`
	Description                 types.String `tfsdk:"description"`
	Label                       types.String `tfsdk:"label"`
	LongDescription             types.String `tfsdk:"long_description"`
	Filter                      types.String `tfsdk:"filter"`
	Level                       types.Int64  `tfsdk:"level"`
	Severity                    types.String `tfsdk:"severity"`
	Tags                        types.List   `tfsdk:"tags"`
	Categories                  types.List   `tfsdk:"categories"`
	SnapshotFiles               types.List   `tfsdk:"snapshot_files"`
	AddToJamfProSmartGroup      types.Bool   `tfsdk:"add_to_jamf_pro_smart_group"`
	JamfProSmartGroupIdentifier types.String `tfsdk:"jamf_pro_smart_group_identifier"`
	TenantActions               types.Set    `tfsdk:"tenant_actions"`
	TenantSeverity              types.String `tfsdk:"tenant_severity"`
	ContextItem                 types.Set    `tfsdk:"context_item"`
	Created                     types.String `tfsdk:"created"`
	Updated                     types.String `tfsdk:"updated"`
	Jamf                        types.Bool   `tfsdk:"jamf"`
	Remediation                 types.String `tfsdk:"remediation"`
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
		"sensor_type": schema.StringAttribute{
			MarkdownDescription: "The sensor type for the analytic.",
			Computed:            true,
		},
		"description": schema.StringAttribute{
			MarkdownDescription: "A description of the analytic.",
			Computed:            true,
		},
		"label": schema.StringAttribute{
			MarkdownDescription: "Display label for the analytic (read-only).",
			Computed:            true,
		},
		"long_description": schema.StringAttribute{
			MarkdownDescription: "Long-form description for the analytic (read-only).",
			Computed:            true,
		},
		"filter": schema.StringAttribute{
			MarkdownDescription: "The filter expression.",
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
		"add_to_jamf_pro_smart_group": schema.BoolAttribute{
			MarkdownDescription: "Whether the analytic adds devices to a Jamf Pro Smart Group.",
			Computed:            true,
		},
		"jamf_pro_smart_group_identifier": schema.StringAttribute{
			MarkdownDescription: "Identifier for the Jamf Pro extension attribute.",
			Computed:            true,
		},
		"tenant_actions": schema.SetNestedAttribute{
			MarkdownDescription: "Tenant-level action overrides (Jamf-managed analytics).",
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
		"tenant_severity": schema.StringAttribute{
			MarkdownDescription: "Tenant-level severity override (Jamf-managed analytics).",
			Computed:            true,
		},
		"context_item": schema.SetNestedAttribute{
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
					"expressions": schema.SetAttribute{
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
		"jamf": schema.BoolAttribute{
			MarkdownDescription: "Indicates whether the analytic is Jamf-managed (read-only).",
			Computed:            true,
		},
		"remediation": schema.StringAttribute{
			MarkdownDescription: "Remediation guidance associated with the analytic (read-only).",
			Computed:            true,
		},
	}
}

func (d *AnalyticsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *AnalyticsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AnalyticsDataSourceModel

	items, err := d.service.ListAnalytics(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing analytics", err.Error())
		return
	}

	tflog.Trace(ctx, "listed analytics", map[string]any{"count": len(items)})

	analytics := make([]AnalyticDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := analyticAPIToDataSourceItem(api, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		analytics = append(analytics, item)
	}
	data.Analytics = analytics

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// analyticAPIToDataSourceItem maps a Jamf Protect analytic to AnalyticDataSourceItemModel.
func analyticAPIToDataSourceItem(api jamfprotect.Analytic, diags *diag.Diagnostics) AnalyticDataSourceItemModel {
	item := AnalyticDataSourceItemModel{
		ID:         types.StringValue(api.UUID),
		Name:       types.StringValue(api.Name),
		SensorType: types.StringValue(mapSensorTypeAPIToUI(api.InputType, diags)),
		Filter:     types.StringValue(normalizeFilterValue(api.Filter)),
		Level:      types.Int64Value(api.Level),
		Severity:   types.StringValue(api.Severity),
		Created:    types.StringValue(api.Created),
		Updated:    types.StringValue(api.Updated),
	}

	if api.Label != "" {
		item.Label = types.StringValue(api.Label)
	} else {
		item.Label = types.StringNull()
	}

	if api.Description != "" {
		item.Description = types.StringValue(api.Description)
	} else {
		item.Description = types.StringNull()
	}

	if api.LongDescription != "" {
		item.LongDescription = types.StringValue(api.LongDescription)
	} else {
		item.LongDescription = types.StringNull()
	}

	item.Tags = common.SortedStringsToList(api.Tags)
	item.Categories = common.SortedStringsToList(api.Categories)
	item.SnapshotFiles = common.SortedStringsToList(api.SnapshotFiles)

	item.AddToJamfProSmartGroup = types.BoolValue(false)
	item.JamfProSmartGroupIdentifier = types.StringNull()
	for _, action := range api.AnalyticActions {
		if action.Name != "SmartGroup" {
			continue
		}
		item.AddToJamfProSmartGroup = types.BoolValue(true)
		if action.Parameters != "" && action.Parameters != "{}" {
			var paramMap map[string]string
			if err := json.Unmarshal([]byte(action.Parameters), &paramMap); err != nil {
				diags.AddError("Error decoding Smart Group parameters",
					fmt.Sprintf("Failed to parse parameters JSON %q: %s", action.Parameters, err.Error()))
				break
			}
			if id, ok := paramMap["id"]; ok && id != "" {
				item.JamfProSmartGroupIdentifier = types.StringValue(id)
			}
		}
		break
	}

	item.TenantActions = apiActionsToSet(api.TenantActions, true, diags)

	if api.TenantSeverity != "" {
		item.TenantSeverity = types.StringValue(api.TenantSeverity)
	} else {
		item.TenantSeverity = types.StringNull()
	}

	// Context.
	var ctxVals []attr.Value
	for _, c := range api.Context {
		ctxVals = append(ctxVals, types.ObjectValueMust(analyticContextAttrTypes, map[string]attr.Value{
			"name":        types.StringValue(c.Name),
			"type":        types.StringValue(c.Type),
			"expressions": common.StringsToSet(c.Exprs),
		}))
	}
	if len(ctxVals) == 0 {
		item.ContextItem = types.SetValueMust(types.ObjectType{AttrTypes: analyticContextAttrTypes}, []attr.Value{})
	} else {
		ctxSet, d := types.SetValue(types.ObjectType{AttrTypes: analyticContextAttrTypes}, ctxVals)
		diags.Append(d...)
		item.ContextItem = ctxSet
	}

	item.Jamf = types.BoolValue(api.Jamf)

	if api.Remediation != "" {
		item.Remediation = types.StringValue(api.Remediation)
	} else {
		item.Remediation = types.StringNull()
	}

	return item
}
