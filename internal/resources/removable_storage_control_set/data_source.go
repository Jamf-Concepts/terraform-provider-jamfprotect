// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &RemovableStorageControlSetsDataSource{}

// NewRemovableStorageControlSetsDataSource returns a new removable storage control sets data source.
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
	ID                              types.String                                 `tfsdk:"id"`
	Name                            types.String                                 `tfsdk:"name"`
	Description                     types.String                                 `tfsdk:"description"`
	DefaultPermission               types.String                                 `tfsdk:"default_permission"`
	DefaultLocalNotificationMessage types.String                                 `tfsdk:"default_local_notification_message"`
	OverrideEncryptedDevices        []RemovableStorageEncryptedOverrideDataModel `tfsdk:"override_encrypted_devices"`
	OverrideVendorID                []RemovableStorageVendorOverrideDataModel    `tfsdk:"override_vendor_id"`
	OverrideProductID               []RemovableStorageProductOverrideDataModel   `tfsdk:"override_product_id"`
	OverrideSerialNumber            []RemovableStorageSerialOverrideDataModel    `tfsdk:"override_serial_number"`
	Created                         types.String                                 `tfsdk:"created"`
	Updated                         types.String                                 `tfsdk:"updated"`
}

// RemovableStorageEncryptedOverrideDataModel represents encrypted device overrides (read-only).
type RemovableStorageEncryptedOverrideDataModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
}

// RemovableStorageVendorOverrideDataModel represents vendor ID overrides (read-only).
type RemovableStorageVendorOverrideDataModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
	ApplyTo                  types.String `tfsdk:"apply_to"`
	VendorIDs                types.List   `tfsdk:"vendor_ids"`
}

// RemovableStorageSerialOverrideDataModel represents serial number overrides (read-only).
type RemovableStorageSerialOverrideDataModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
	ApplyTo                  types.String `tfsdk:"apply_to"`
	SerialNumbers            types.List   `tfsdk:"serial_numbers"`
}

// RemovableStorageProductOverrideDataModel represents product ID overrides (read-only).
type RemovableStorageProductOverrideDataModel struct {
	Permission               types.String                               `tfsdk:"permission"`
	LocalNotificationMessage types.String                               `tfsdk:"local_notification_message"`
	ApplyTo                  types.String                               `tfsdk:"apply_to"`
	ProductIDs               []RemovableStorageProductIDDataSourceModel `tfsdk:"product_id"`
}

// RemovableStorageProductIDDataSourceModel represents a vendor+product pair (read-only).
type RemovableStorageProductIDDataSourceModel struct {
	VendorID  types.String `tfsdk:"vendor_id"`
	ProductID types.String `tfsdk:"product_id"`
}

func (d *RemovableStorageControlSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_sets"
}

// Schema defines the removable storage control sets data source schema.
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
						"default_permission": schema.StringAttribute{
							MarkdownDescription: "The default permission for removable storage devices.",
							Computed:            true,
						},
						"default_local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The default local notification message for removable storage devices.",
							Computed:            true,
						},
						"created": schema.StringAttribute{
							MarkdownDescription: "The creation timestamp.",
							Computed:            true,
						},
						"updated": schema.StringAttribute{
							MarkdownDescription: "The last-updated timestamp.",
							Computed:            true,
						},
						"override_encrypted_devices": schema.ListNestedAttribute{
							MarkdownDescription: "Overrides applied to encrypted devices.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"permission": schema.StringAttribute{
										MarkdownDescription: "The permission for matching devices.",
										Computed:            true,
									},
									"local_notification_message": schema.StringAttribute{
										MarkdownDescription: "The local notification message for this override.",
										Computed:            true,
									},
								},
							},
						},
						"override_vendor_id": schema.ListNestedAttribute{
							MarkdownDescription: "Overrides applied to vendor IDs.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"permission": schema.StringAttribute{
										MarkdownDescription: "The permission for matching devices.",
										Computed:            true,
									},
									"local_notification_message": schema.StringAttribute{
										MarkdownDescription: "The local notification message for this override.",
										Computed:            true,
									},
									"apply_to": schema.StringAttribute{
										MarkdownDescription: "The scope this override applies to.",
										Computed:            true,
									},
									"vendor_ids": schema.ListAttribute{
										MarkdownDescription: "Vendor IDs this override applies to.",
										Computed:            true,
										ElementType:         types.StringType,
									},
								},
							},
						},
						"override_product_id": schema.ListNestedAttribute{
							MarkdownDescription: "Overrides applied to product IDs.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"permission": schema.StringAttribute{
										MarkdownDescription: "The permission for matching devices.",
										Computed:            true,
									},
									"local_notification_message": schema.StringAttribute{
										MarkdownDescription: "The local notification message for this override.",
										Computed:            true,
									},
									"apply_to": schema.StringAttribute{
										MarkdownDescription: "The scope this override applies to.",
										Computed:            true,
									},
									"product_id": schema.ListNestedAttribute{
										MarkdownDescription: "Vendor and product IDs this override applies to.",
										Computed:            true,
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"vendor_id": schema.StringAttribute{
													MarkdownDescription: "The vendor ID.",
													Computed:            true,
												},
												"product_id": schema.StringAttribute{
													MarkdownDescription: "The product ID.",
													Computed:            true,
												},
											},
										},
									},
								},
							},
						},
						"override_serial_number": schema.ListNestedAttribute{
							MarkdownDescription: "Overrides applied to serial numbers.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"permission": schema.StringAttribute{
										MarkdownDescription: "The permission for matching devices.",
										Computed:            true,
									},
									"local_notification_message": schema.StringAttribute{
										MarkdownDescription: "The local notification message for this override.",
										Computed:            true,
									},
									"apply_to": schema.StringAttribute{
										MarkdownDescription: "The scope this override applies to.",
										Computed:            true,
									},
									"serial_numbers": schema.ListAttribute{
										MarkdownDescription: "Serial numbers this override applies to.",
										Computed:            true,
										ElementType:         types.StringType,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Configure prepares the removable storage control set service client.
func (d *RemovableStorageControlSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// Read retrieves removable storage control sets from the API.
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
			ID:                              types.StringValue(api.ID),
			Name:                            types.StringValue(api.Name),
			DefaultPermission:               types.StringValue(permissionFromAPI(api.DefaultMountAction)),
			Description:                     types.StringValue(api.Description),
			DefaultLocalNotificationMessage: types.StringValue(api.DefaultMessageAction),
			Created:                         types.StringValue(api.Created),
			Updated:                         types.StringValue(api.Updated),
		}

		encryptedOverrides := make([]RemovableStorageEncryptedOverrideDataModel, 0)
		vendorOverrides := make([]RemovableStorageVendorOverrideDataModel, 0)
		serialOverrides := make([]RemovableStorageSerialOverrideDataModel, 0)
		productOverrides := make([]RemovableStorageProductOverrideDataModel, 0)

		for _, apiRule := range api.Rules {
			ruleType := normalizeRemovableStorageRuleType(apiRule.Type)
			localMessage := types.StringNull()
			if apiRule.MessageAction != "" {
				localMessage = types.StringValue(apiRule.MessageAction)
			}
			applyTo := types.StringNull()
			if apiRule.ApplyTo != "" {
				applyTo = types.StringValue(apiRule.ApplyTo)
			}

			permission := types.StringValue(permissionFromAPI(apiRule.MountAction))

			switch ruleType {
			case "Encryption":
				encryptedOverrides = append(encryptedOverrides, RemovableStorageEncryptedOverrideDataModel{
					Permission:               permission,
					LocalNotificationMessage: localMessage,
				})
			case "Vendor":
				vendorOverrides = append(vendorOverrides, RemovableStorageVendorOverrideDataModel{
					Permission:               permission,
					LocalNotificationMessage: localMessage,
					ApplyTo:                  applyTo,
					VendorIDs:                common.StringsToList(apiRule.Vendors),
				})
			case "Serial":
				serialOverrides = append(serialOverrides, RemovableStorageSerialOverrideDataModel{
					Permission:               permission,
					LocalNotificationMessage: localMessage,
					ApplyTo:                  applyTo,
					SerialNumbers:            common.StringsToList(apiRule.Serials),
				})
			case "Product":
				products := make([]RemovableStorageProductIDDataSourceModel, 0, len(apiRule.Products))
				for _, p := range apiRule.Products {
					products = append(products, RemovableStorageProductIDDataSourceModel{
						VendorID:  types.StringValue(p.Vendor),
						ProductID: types.StringValue(p.Product),
					})
				}
				productOverrides = append(productOverrides, RemovableStorageProductOverrideDataModel{
					Permission:               permission,
					LocalNotificationMessage: localMessage,
					ApplyTo:                  applyTo,
					ProductIDs:               products,
				})
			}
		}

		item.OverrideEncryptedDevices = encryptedOverrides
		item.OverrideVendorID = vendorOverrides
		item.OverrideSerialNumber = serialOverrides
		item.OverrideProductID = productOverrides

		items = append(items, item)
	}
	data.RemovableStorageControlSets = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
