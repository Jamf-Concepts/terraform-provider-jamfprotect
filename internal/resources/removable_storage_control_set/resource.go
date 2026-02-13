// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"
	"fmt"
	"time"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

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
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ resource.Resource = &USBControlSetResource{}
var _ resource.ResourceWithImportState = &USBControlSetResource{}

func NewUSBControlSetResource() resource.Resource {
	return &USBControlSetResource{}
}

// USBControlSetResource manages a Jamf Protect USB control set.
type USBControlSetResource struct {
	client *client.Client
}

func (r *USBControlSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_set"
}

func (r *USBControlSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	mountActionValidator := stringvalidator.OneOf("ReadOnly", "ReadWrite", "Prevented")
	ruleTypeValidator := stringvalidator.OneOf("Vendor", "Serial", "Product", "Encryption", "VendorRule", "SerialRule", "ProductRule", "EncryptionRule")

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a USB control set in Jamf Protect. USB control sets define policies for removable storage device access, including default mount behavior and vendor/serial/product-specific rules.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the USB control set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the USB control set.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the USB control set.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"default_mount_action": schema.StringAttribute{
				MarkdownDescription: "The default mount action for USB devices. Valid values: `ReadOnly`, `ReadWrite`, `Prevented`.",
				Required:            true,
				Validators:          []validator.String{mountActionValidator},
			},
			"default_message_action": schema.StringAttribute{
				MarkdownDescription: "The default message displayed to users when a USB device action is triggered.",
				Optional:            true,
				Computed:            true,
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "A list of USB control rules. Each rule targets devices by vendor ID, serial number, or product ID.",
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

func (r *USBControlSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *USBControlSetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data USBControlSetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := data.Timeouts.Create(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var result struct {
		CreateUSBControlSet usbControlSetAPIModel `json:"createUSBControlSet"`
	}
	if err := r.client.Query(ctx, createUSBControlSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating USB control set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateUSBControlSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created USB control set", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *USBControlSetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data USBControlSetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := data.Timeouts.Read(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	vars := map[string]any{"id": data.ID.ValueString()}
	var result struct {
		GetUSBControlSet *usbControlSetAPIModel `json:"getUSBControlSet"`
	}
	if err := r.client.Query(ctx, getUSBControlSetQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading USB control set", err.Error())
		return
	}
	if result.GetUSBControlSet == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetUSBControlSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *USBControlSetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data USBControlSetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state USBControlSetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	updateTimeout, diags := data.Timeouts.Update(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	vars["id"] = data.ID.ValueString()

	var result struct {
		UpdateUSBControlSet usbControlSetAPIModel `json:"updateUSBControlSet"`
	}
	if err := r.client.Query(ctx, updateUSBControlSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating USB control set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateUSBControlSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *USBControlSetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data USBControlSetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := data.Timeouts.Delete(ctx, 30*time.Second)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	vars := map[string]any{"id": data.ID.ValueString()}
	if err := r.client.Query(ctx, deleteUSBControlSetMutation, vars, nil); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "USB control set already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting USB control set", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted USB control set", map[string]any{"id": data.ID.ValueString()})
}

func (r *USBControlSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
