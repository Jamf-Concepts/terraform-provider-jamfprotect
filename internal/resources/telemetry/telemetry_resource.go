// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ resource.Resource = &TelemetryV2Resource{}
var _ resource.ResourceWithImportState = &TelemetryV2Resource{}

func NewTelemetryV2Resource() resource.Resource {
	return &TelemetryV2Resource{}
}

// TelemetryV2Resource manages a Jamf Protect telemetry v2 configuration.
type TelemetryV2Resource struct {
	client *client.Client
}

func (r *TelemetryV2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_telemetry"
}

func (r *TelemetryV2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a telemetry v2 configuration in Jamf Protect. Telemetry configurations define which endpoint security events, log files, and performance metrics are collected from managed endpoints.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the telemetry v2 configuration.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the telemetry v2 configuration.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the telemetry v2 configuration.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"log_files": schema.ListAttribute{
				MarkdownDescription: "A list of log file paths to collect from endpoints.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"log_file_collection": schema.BoolAttribute{
				MarkdownDescription: "Whether log file collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"performance_metrics": schema.BoolAttribute{
				MarkdownDescription: "Whether performance metrics collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"events": schema.ListAttribute{
				MarkdownDescription: "A list of endpoint security events to collect (e.g. `authentication`, `exec`, `mount`, `sudo`).",
				Required:            true,
				ElementType:         types.StringType,
			},
			"file_hashing": schema.BoolAttribute{
				MarkdownDescription: "Whether file hashing is enabled for telemetry events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
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

func (r *TelemetryV2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TelemetryV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TelemetryV2ResourceModel
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
		CreateTelemetryV2 telemetryV2APIModel `json:"createTelemetryV2"`
	}
	if err := r.client.Query(ctx, createTelemetryV2Mutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating telemetry v2 configuration", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateTelemetryV2, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "created telemetry v2 configuration", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TelemetryV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TelemetryV2ResourceModel
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
		GetTelemetryV2 *telemetryV2APIModel `json:"getTelemetryV2"`
	}
	if err := r.client.Query(ctx, getTelemetryV2Query, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading telemetry v2 configuration", err.Error())
		return
	}
	if result.GetTelemetryV2 == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetTelemetryV2, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TelemetryV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TelemetryV2ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state TelemetryV2ResourceModel
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
		UpdateTelemetryV2 telemetryV2APIModel `json:"updateTelemetryV2"`
	}
	if err := r.client.Query(ctx, updateTelemetryV2Mutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating telemetry v2 configuration", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateTelemetryV2, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TelemetryV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TelemetryV2ResourceModel
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
	if err := r.client.Query(ctx, deleteTelemetryV2Mutation, vars, nil); err != nil {
		if common.IsNotFoundError(err) {
			tflog.Trace(ctx, "telemetry v2 configuration already deleted", map[string]any{"id": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting telemetry v2 configuration", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted telemetry v2 configuration", map[string]any{"id": data.ID.ValueString()})
}

func (r *TelemetryV2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
