// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

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

var _ datasource.DataSource = &USBControlSetsDataSource{}

func NewUSBControlSetsDataSource() datasource.DataSource {
	return &USBControlSetsDataSource{}
}

// USBControlSetsDataSource lists all USB control sets in Jamf Protect.
type USBControlSetsDataSource struct {
	client *client.Client
}

// USBControlSetsDataSourceModel maps the data source schema.
type USBControlSetsDataSourceModel struct {
	USBControlSets []USBControlSetDataSourceItemModel `tfsdk:"removable_storage_control_sets"`
}

// USBControlSetDataSourceItemModel maps a single USB control set item (read-only, no timeouts).
type USBControlSetDataSourceItemModel struct {
	ID                   types.String                 `tfsdk:"id"`
	Name                 types.String                 `tfsdk:"name"`
	Description          types.String                 `tfsdk:"description"`
	DefaultMountAction   types.String                 `tfsdk:"default_mount_action"`
	DefaultMessageAction types.String                 `tfsdk:"default_message_action"`
	Rules                []USBRuleDataSourceItemModel `tfsdk:"rules"`
	Created              types.String                 `tfsdk:"created"`
	Updated              types.String                 `tfsdk:"updated"`
}

// USBRuleDataSourceItemModel represents a single rule in the USB control set (read-only).
type USBRuleDataSourceItemModel struct {
	Type          types.String                    `tfsdk:"type"`
	MountAction   types.String                    `tfsdk:"mount_action"`
	MessageAction types.String                    `tfsdk:"message_action"`
	ApplyTo       types.String                    `tfsdk:"apply_to"`
	Vendors       types.List                      `tfsdk:"vendors"`
	Serials       types.List                      `tfsdk:"serials"`
	Products      []USBProductDataSourceItemModel `tfsdk:"products"`
}

// USBProductDataSourceItemModel represents a vendor+product pair (read-only).
type USBProductDataSourceItemModel struct {
	Vendor  types.String `tfsdk:"vendor"`
	Product types.String `tfsdk:"product"`
}

func (d *USBControlSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_sets"
}

func (d *USBControlSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all USB control sets in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"removable_storage_control_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of USB control sets.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the USB control set.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the USB control set.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the USB control set.",
							Computed:            true,
						},
						"default_mount_action": schema.StringAttribute{
							MarkdownDescription: "The default mount action for USB devices.",
							Computed:            true,
						},
						"default_message_action": schema.StringAttribute{
							MarkdownDescription: "The default message action for USB devices.",
							Computed:            true,
						},
						"rules": schema.ListNestedAttribute{
							MarkdownDescription: "The USB control rules.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										MarkdownDescription: "The rule type (Vendor, Serial, Product, or Encryption).",
										Computed:            true,
									},
									"mount_action": schema.StringAttribute{
										MarkdownDescription: "The mount action for this rule.",
										Computed:            true,
									},
									"message_action": schema.StringAttribute{
										MarkdownDescription: "The message action for this rule.",
										Computed:            true,
									},
									"apply_to": schema.StringAttribute{
										MarkdownDescription: "The scope this rule applies to.",
										Computed:            true,
									},
									"vendors": schema.ListAttribute{
										MarkdownDescription: "Vendor identifiers (for VendorRule type).",
										Computed:            true,
										ElementType:         types.StringType,
									},
									"serials": schema.ListAttribute{
										MarkdownDescription: "Serial numbers (for SerialRule type).",
										Computed:            true,
										ElementType:         types.StringType,
									},
									"products": schema.ListNestedAttribute{
										MarkdownDescription: "Vendor+product pairs (for ProductRule type).",
										Computed:            true,
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"vendor": schema.StringAttribute{
													MarkdownDescription: "The vendor identifier.",
													Computed:            true,
												},
												"product": schema.StringAttribute{
													MarkdownDescription: "The product identifier.",
													Computed:            true,
												},
											},
										},
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
					},
				},
			},
		},
	}
}

func (d *USBControlSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *USBControlSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data USBControlSetsDataSourceModel

	var allItems []usbControlSetAPIModel
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
			ListUSBControlSets struct {
				Items    []usbControlSetAPIModel `json:"items"`
				PageInfo common.PageInfo         `json:"pageInfo"`
			} `json:"listUSBControlSets"`
		}
		if err := d.client.Query(ctx, listUSBControlSetsQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing USB control sets", err.Error())
			return
		}

		allItems = append(allItems, result.ListUSBControlSets.Items...)

		if result.ListUSBControlSets.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListUSBControlSets.PageInfo.Next
	}

	tflog.Trace(ctx, "listed USB control sets", map[string]any{"count": len(allItems)})

	items := make([]USBControlSetDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := USBControlSetDataSourceItemModel{
			ID:                 types.StringValue(api.ID),
			Name:               types.StringValue(api.Name),
			DefaultMountAction: types.StringValue(api.DefaultMountAction),
			Created:            types.StringValue(api.Created),
			Updated:            types.StringValue(api.Updated),
		}

		if api.Description != "" {
			item.Description = types.StringValue(api.Description)
		} else {
			item.Description = types.StringNull()
		}

		if api.DefaultMessageAction != "" {
			item.DefaultMessageAction = types.StringValue(api.DefaultMessageAction)
		} else {
			item.DefaultMessageAction = types.StringNull()
		}

		rules := make([]USBRuleDataSourceItemModel, 0, len(api.Rules))
		for _, apiRule := range api.Rules {
			rule := USBRuleDataSourceItemModel{
				Type:        types.StringValue(normalizeUSBRuleType(apiRule.Type)),
				MountAction: types.StringValue(apiRule.MountAction),
			}

			if apiRule.MessageAction != "" {
				rule.MessageAction = types.StringValue(apiRule.MessageAction)
			} else {
				rule.MessageAction = types.StringNull()
			}

			if apiRule.ApplyTo != "" {
				rule.ApplyTo = types.StringValue(apiRule.ApplyTo)
			} else {
				rule.ApplyTo = types.StringNull()
			}

			switch normalizeUSBRuleType(apiRule.Type) {
			case "Vendor":
				rule.Vendors = common.StringsToList(apiRule.Vendors)
				rule.Serials = types.ListNull(types.StringType)
			case "Serial":
				rule.Serials = common.StringsToList(apiRule.Serials)
				rule.Vendors = types.ListNull(types.StringType)
			case "Product":
				products := make([]USBProductDataSourceItemModel, 0, len(apiRule.Products))
				for _, p := range apiRule.Products {
					products = append(products, USBProductDataSourceItemModel{
						Vendor:  types.StringValue(p.Vendor),
						Product: types.StringValue(p.Product),
					})
				}
				rule.Products = products
				rule.Vendors = types.ListNull(types.StringType)
				rule.Serials = types.ListNull(types.StringType)
			default:
				rule.Vendors = types.ListNull(types.StringType)
				rule.Serials = types.ListNull(types.StringType)
			}

			rules = append(rules, rule)
		}
		item.Rules = rules

		items = append(items, item)
	}
	data.USBControlSets = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
