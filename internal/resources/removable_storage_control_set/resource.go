// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &RemovableStorageControlSetResource{}
var _ resource.ResourceWithImportState = &RemovableStorageControlSetResource{}

func NewRemovableStorageControlSetResource() resource.Resource {
	return &RemovableStorageControlSetResource{}
}

// RemovableStorageControlSetResource manages a Jamf Protect removable storage control set.
type RemovableStorageControlSetResource struct {
	service *jamfprotect.Service
}

func (r *RemovableStorageControlSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_set"
}

func (r *RemovableStorageControlSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	permissionValidator := stringvalidator.OneOf("ReadOnly", "ReadWrite", "Prevented")

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a removable storage control set in Jamf Protect. Removable storage control sets define policies for removable storage device access, including default permissions and device-specific overrides for encrypted devices, vendors, serial numbers, and product IDs.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the removable storage control set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the removable storage control set.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the removable storage control set.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"default_permission": schema.StringAttribute{
				MarkdownDescription: "The default permission for removable storage devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
				Required:            true,
				Validators:          []validator.String{permissionValidator},
			},
			"default_local_notification_message": schema.StringAttribute{
				MarkdownDescription: "The default local notification message displayed to users when a removable storage device action is triggered.",
				Optional:            true,
				Computed:            true,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last update timestamp.",
				Computed:            true,
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
		Blocks: map[string]schema.Block{
			"override_encrypted_devices": schema.ListNestedBlock{
				MarkdownDescription: "Overrides applied to encrypted devices.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: "The permission for matching devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
					},
				},
			},
			"override_vendor_id": schema.ListNestedBlock{
				MarkdownDescription: "Overrides applied to vendor IDs.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: "The permission for matching devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"vendor_ids": schema.ListAttribute{
							MarkdownDescription: "A list of vendor IDs that this override applies to.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"override_product_id": schema.ListNestedBlock{
				MarkdownDescription: "Overrides applied to product IDs.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: "The permission for matching devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"product_id": schema.ListNestedAttribute{
							MarkdownDescription: "Vendor and product IDs that this override applies to.",
							Required:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"vendor_id": schema.StringAttribute{
										MarkdownDescription: "The vendor ID.",
										Required:            true,
									},
									"product_id": schema.StringAttribute{
										MarkdownDescription: "The product ID.",
										Required:            true,
									},
								},
							},
						},
					},
				},
			},
			"override_serial_number": schema.ListNestedBlock{
				MarkdownDescription: "Overrides applied to serial numbers.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: "The permission for matching devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"serial_numbers": schema.ListAttribute{
							MarkdownDescription: "A list of serial numbers that this override applies to.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
		},
	}
}

func (r *RemovableStorageControlSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.service = jamfprotect.NewService(client)
}

func (r *RemovableStorageControlSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
