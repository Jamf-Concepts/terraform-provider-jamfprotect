// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ resource.Resource = &ActionConfigResource{}
var _ resource.ResourceWithImportState = &ActionConfigResource{}

func NewActionConfigResource() resource.Resource {
	return &ActionConfigResource{}
}

// ActionConfigResource manages a Jamf Protect action configuration.
type ActionConfigResource struct {
	client *client.Client
}

func (r *ActionConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_action_config"
}

func (r *ActionConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	eventTypeAttrs := map[string]schema.Attribute{
		"attrs": schema.ListAttribute{
			MarkdownDescription: "Attribute names to include in alert data for this event type.",
			Required:            true,
			ElementType:         types.StringType,
		},
		"related": schema.ListAttribute{
			MarkdownDescription: "Related object types to include in alert data (e.g. `file`, `process`, `user`).",
			Required:            true,
			ElementType:         types.StringType,
		},
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an action configuration in Jamf Protect. Action configurations define the alert data enrichment settings and reporting clients for a plan.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the action configuration.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hash": schema.StringAttribute{
				MarkdownDescription: "The configuration hash.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the action configuration.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the action configuration.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"alert_config": schema.SingleNestedAttribute{
				MarkdownDescription: "Alert configuration defining which data attributes and related objects to include in alerts for each event type.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"data": schema.SingleNestedAttribute{
						MarkdownDescription: "Data enrichment settings per event type.",
						Required:            true,
						Attributes: map[string]schema.Attribute{
							"binary": schema.SingleNestedAttribute{
								MarkdownDescription: "Binary/executable metadata enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"click_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Click event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"download_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Download event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"file": schema.SingleNestedAttribute{
								MarkdownDescription: "File metadata enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"fs_event": schema.SingleNestedAttribute{
								MarkdownDescription: "File system event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"group": schema.SingleNestedAttribute{
								MarkdownDescription: "Group metadata enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"proc_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Process event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"process": schema.SingleNestedAttribute{
								MarkdownDescription: "Process metadata enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"screenshot_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Screenshot event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"usb_event": schema.SingleNestedAttribute{
								MarkdownDescription: "USB device event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"user": schema.SingleNestedAttribute{
								MarkdownDescription: "User metadata enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"gk_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Gatekeeper event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"keylog_register_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Keylogger registration event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
							},
							"mrt_event": schema.SingleNestedAttribute{
								MarkdownDescription: "Malware Removal Tool event enrichment.",
								Required:            true,
								Attributes:          eventTypeAttrs,
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
				MarkdownDescription: "The last-updated timestamp.",
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

func (r *ActionConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ActionConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ActionConfigResourceModel
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
		CreateActionConfigs actionConfigAPIModel `json:"createActionConfigs"`
	}
	if err := r.client.Query(ctx, createActionConfigMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating action config", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateActionConfigs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created action config", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ActionConfigResourceModel
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
		GetActionConfigs *actionConfigAPIModel `json:"getActionConfigs"`
	}
	if err := r.client.Query(ctx, getActionConfigQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading action config", err.Error())
		return
	}
	if result.GetActionConfigs == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetActionConfigs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ActionConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ActionConfigResourceModel
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
		UpdateActionConfigs actionConfigAPIModel `json:"updateActionConfigs"`
	}
	if err := r.client.Query(ctx, updateActionConfigMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating action config", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateActionConfigs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ActionConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ActionConfigResourceModel
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
	if err := r.client.Query(ctx, deleteActionConfigMutation, vars, nil); err != nil {
		if isNotFoundError(err) {
			tflog.Trace(ctx, "action config already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting action config", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted action config", map[string]any{"id": data.ID.ValueString()})
}

func (r *ActionConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
