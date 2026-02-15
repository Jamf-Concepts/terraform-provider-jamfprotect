// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &RemovableStorageControlSetsDataSource{}

func NewRemovableStorageControlSetsDataSource() datasource.DataSource {
	return &RemovableStorageControlSetsDataSource{}
}

// RemovableStorageControlSetsDataSource lists all removable storage control sets in Jamf Protect.
type RemovableStorageControlSetsDataSource struct {
	service *jamfprotect.Service
}

// RemovableStorageControlSetsDataSourceModel maps the data source schema.
type RemovableStorageControlSetsDataSourceModel struct {
	RemovableStorageControlSets []RemovableStorageControlSetDataSourceItemModel `tfsdk:"removable_storage_control_sets"`
}

// RemovableStorageControlSetDataSourceItemModel maps a single removable storage control set item (read-only, no timeouts).
type RemovableStorageControlSetDataSourceItemModel struct {
	ID                   types.String                              `tfsdk:"id"`
	Name                 types.String                              `tfsdk:"name"`
	Description          types.String                              `tfsdk:"description"`
	DefaultMountAction   types.String                              `tfsdk:"default_mount_action"`
	DefaultMessageAction types.String                              `tfsdk:"default_message_action"`
	Rules                []RemovableStorageRuleDataSourceItemModel `tfsdk:"rules"`
	Created              types.String                              `tfsdk:"created"`
	Updated              types.String                              `tfsdk:"updated"`
}

// RemovableStorageRuleDataSourceItemModel represents a single rule in the removable storage control set (read-only).
type RemovableStorageRuleDataSourceItemModel struct {
	Type          types.String                                 `tfsdk:"type"`
	MountAction   types.String                                 `tfsdk:"mount_action"`
	MessageAction types.String                                 `tfsdk:"message_action"`
	ApplyTo       types.String                                 `tfsdk:"apply_to"`
	Vendors       types.List                                   `tfsdk:"vendors"`
	Serials       types.List                                   `tfsdk:"serials"`
	Products      []RemovableStorageProductDataSourceItemModel `tfsdk:"products"`
}

// RemovableStorageProductDataSourceItemModel represents a vendor+product pair (read-only).
type RemovableStorageProductDataSourceItemModel struct {
	Vendor  types.String `tfsdk:"vendor"`
	Product types.String `tfsdk:"product"`
}

func (d *RemovableStorageControlSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_sets"
}

func (d *RemovableStorageControlSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all removable storage control sets in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"removable_storage_control_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of removable storage control sets.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The unique identifier of the removable storage control set.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The name of the removable storage control set.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A description of the removable storage control set.",
							Computed:            true,
						},
						"default_mount_action": schema.StringAttribute{
							MarkdownDescription: "The default mount action for removable storage devices.",
							Computed:            true,
						},
						"default_message_action": schema.StringAttribute{
							MarkdownDescription: "The default message action for removable storage devices.",
							Computed:            true,
						},
						"rules": schema.ListNestedAttribute{
							MarkdownDescription: "The removable storage control rules.",
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

func (d *RemovableStorageControlSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	d.service = jamfprotect.NewService(client)
}

func (d *RemovableStorageControlSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RemovableStorageControlSetsDataSourceModel

	allItems, err := d.service.ListRemovableStorageControlSets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing removable storage control sets", err.Error())
		return
	}

	tflog.Trace(ctx, "listed removable storage control sets", map[string]any{"count": len(allItems)})

	items := make([]RemovableStorageControlSetDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
		item := RemovableStorageControlSetDataSourceItemModel{
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

		rules := make([]RemovableStorageRuleDataSourceItemModel, 0, len(api.Rules))
		for _, apiRule := range api.Rules {
			ruleType := normalizeRemovableStorageRuleType(apiRule.Type)
			rule := RemovableStorageRuleDataSourceItemModel{
				Type:        types.StringValue(ruleType),
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

			switch ruleType {
			case "Vendor":
				rule.Vendors = common.StringsToList(apiRule.Vendors)
				rule.Serials = types.ListNull(types.StringType)
				rule.Products = nil
			case "Serial":
				rule.Serials = common.StringsToList(apiRule.Serials)
				rule.Vendors = types.ListNull(types.StringType)
				rule.Products = nil
			case "Product":
				products := make([]RemovableStorageProductDataSourceItemModel, 0, len(apiRule.Products))
				for _, p := range apiRule.Products {
					products = append(products, RemovableStorageProductDataSourceItemModel{
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
				rule.Products = nil
			}

			rules = append(rules, rule)
		}
		item.Rules = rules

		items = append(items, item)
	}
	data.RemovableStorageControlSets = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
