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
	mountActionValidator := stringvalidator.OneOf("ReadOnly", "ReadWrite", "Prevented")
	ruleTypeValidator := stringvalidator.OneOf("Vendor", "Serial", "Product", "Encryption", "VendorRule", "SerialRule", "ProductRule", "EncryptionRule")

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a removable storage control set in Jamf Protect. Removable storage control sets define policies for removable storage device access, including default mount behavior and vendor/serial/product-specific rules.",
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
			"default_mount_action": schema.StringAttribute{
				MarkdownDescription: "The default mount action for removable storage devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
				Required:            true,
				Validators:          []validator.String{mountActionValidator},
			},
			"default_message_action": schema.StringAttribute{
				MarkdownDescription: "The default message displayed to users when a removable storage device action is triggered.",
				Optional:            true,
				Computed:            true,
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "A list of removable storage control rules. Each rule targets devices by vendor ID, serial number, or product ID.",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of rule. Valid values: `Vendor`, `Serial`, `Product`, `Encryption`.",
							Required:            true,
							Validators:          []validator.String{ruleTypeValidator},
						},
						"mount_action": schema.StringAttribute{
							MarkdownDescription: "The mount action for matching devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
							Required:            true,
							Validators:          []validator.String{mountActionValidator},
						},
						"message_action": schema.StringAttribute{
							MarkdownDescription: "The message displayed to users when this rule is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the rule applies to.",
							Optional:            true,
							Computed:            true,
						},
						"vendors": schema.ListAttribute{
							MarkdownDescription: "A list of vendor IDs (used when type is `VendorRule`).",
							Optional:            true,
							ElementType:         types.StringType,
						},
						"serials": schema.ListAttribute{
							MarkdownDescription: "A list of serial numbers (used when type is `SerialRule`).",
							Optional:            true,
							ElementType:         types.StringType,
						},
						"products": schema.ListNestedAttribute{
							MarkdownDescription: "A list of vendor+product ID pairs (used when type is `ProductRule`).",
							Optional:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"vendor": schema.StringAttribute{
										MarkdownDescription: "The vendor ID.",
										Required:            true,
									},
									"product": schema.StringAttribute{
										MarkdownDescription: "The product ID.",
										Required:            true,
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
