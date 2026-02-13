// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &ExceptionSetResource{}
var _ resource.ResourceWithImportState = &ExceptionSetResource{}

func NewExceptionSetResource() resource.Resource {
	return &ExceptionSetResource{}
}

// ExceptionSetResource manages a Jamf Protect exception set.
type ExceptionSetResource struct {
	client *graphql.Client
}

func (r *ExceptionSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_exception_set"
}

func (r *ExceptionSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	appSigningInfoAttrs := map[string]schema.Attribute{
		"app_id": schema.StringAttribute{
			MarkdownDescription: "The application identifier.",
			Required:            true,
		},
		"team_id": schema.StringAttribute{
			MarkdownDescription: "The team identifier.",
			Required:            true,
		},
	}

	exceptionAttrs := map[string]schema.Attribute{
		"type": schema.StringAttribute{
			MarkdownDescription: "The type of exception (e.g., `SHA256Hash`, `ProcessPath`, `SigningId`).",
			Required:            true,
		},
		"value": schema.StringAttribute{
			MarkdownDescription: "The value to match for this exception.",
			Required:            true,
		},
		"app_signing_info": schema.SingleNestedAttribute{
			MarkdownDescription: "Application signing information for code signature exceptions.",
			Optional:            true,
			Attributes:          appSigningInfoAttrs,
		},
		"ignore_activity": schema.BoolAttribute{
			MarkdownDescription: "Whether to ignore activity matching this exception.",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
		},
		"analytic_types": schema.ListAttribute{
			MarkdownDescription: "The types of analytics this exception applies to (e.g., `Report`, `Prevent`).",
			Optional:            true,
			ElementType:         types.StringType,
		},
	}

	esExceptionAttrs := map[string]schema.Attribute{
		"type": schema.StringAttribute{
			MarkdownDescription: "The type of ES exception.",
			Required:            true,
		},
		"value": schema.StringAttribute{
			MarkdownDescription: "The value to match for this ES exception.",
			Required:            true,
		},
		"app_signing_info": schema.SingleNestedAttribute{
			MarkdownDescription: "Application signing information for code signature exceptions.",
			Optional:            true,
			Attributes:          appSigningInfoAttrs,
		},
		"ignore_activity": schema.BoolAttribute{
			MarkdownDescription: "Whether to ignore activity matching this exception.",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
		},
		"ignore_list_type": schema.StringAttribute{
			MarkdownDescription: "The ignore list type for this ES exception.",
			Required:            true,
		},
		"ignore_list_subtype": schema.StringAttribute{
			MarkdownDescription: "The ignore list subtype for this ES exception.",
			Required:            true,
		},
		"event_type": schema.StringAttribute{
			MarkdownDescription: "The event type for this ES exception.",
			Required:            true,
		},
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an exception set in Jamf Protect. Exception sets define exceptions to analytics and can be associated with plans.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the exception set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the exception set.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the exception set.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"exceptions": schema.ListNestedAttribute{
				MarkdownDescription: "A list of exceptions for analytics.",
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.ObjectType{AttrTypes: exceptionAttrTypes}, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: exceptionAttrs,
				},
			},
			"es_exceptions": schema.ListNestedAttribute{
				MarkdownDescription: "A list of Endpoint Security exceptions.",
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.ObjectType{AttrTypes: esExceptionAttrTypes}, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: esExceptionAttrs,
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
			"managed": schema.BoolAttribute{
				MarkdownDescription: "Whether this is a Jamf-managed exception set.",
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

func (r *ExceptionSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*graphql.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *graphql.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *ExceptionSetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ExceptionSetResourceModel
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
		CreateExceptionSet exceptionSetResourceAPIModel `json:"createExceptionSet"`
	}
	if err := r.client.Query(ctx, createExceptionSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating exception set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreateExceptionSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created exception set", map[string]any{"uuid": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ExceptionSetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ExceptionSetResourceModel
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

	vars := map[string]any{
		"uuid":          data.ID.ValueString(),
		"minimal":       false,
		"RBAC_Analytic": true,
		"RBAC_Plan":     true,
	}
	var result struct {
		GetExceptionSet *exceptionSetResourceAPIModel `json:"getExceptionSet"`
	}
	if err := r.client.Query(ctx, getExceptionSetQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading exception set", err.Error())
		return
	}
	if result.GetExceptionSet == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetExceptionSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ExceptionSetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ExceptionSetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UUID comes from state, not plan.
	var state ExceptionSetResourceModel
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
	vars["uuid"] = data.ID.ValueString()

	var result struct {
		UpdateExceptionSet exceptionSetResourceAPIModel `json:"updateExceptionSet"`
	}
	if err := r.client.Query(ctx, updateExceptionSetMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating exception set", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdateExceptionSet, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ExceptionSetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ExceptionSetResourceModel
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

	vars := map[string]any{"uuid": data.ID.ValueString()}
	if err := r.client.Query(ctx, deleteExceptionSetMutation, vars, nil); err != nil {
		if isNotFoundError(err) {
			tflog.Trace(ctx, "exception set already deleted", map[string]any{"uuid": data.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error deleting exception set", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted exception set", map[string]any{"uuid": data.ID.ValueString()})
}

func (r *ExceptionSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
