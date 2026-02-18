// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &ExceptionSetResource{}
var _ resource.ResourceWithImportState = &ExceptionSetResource{}
var _ resource.ResourceWithIdentity = &ExceptionSetResource{}

func NewExceptionSetResource() resource.Resource {
	return &ExceptionSetResource{}
}

// ExceptionSetResource manages a Jamf Protect exception set.
type ExceptionSetResource struct {
	service *jamfprotect.Service
}

func (r *ExceptionSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_exception_set"
}

func (r *ExceptionSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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
		Blocks: map[string]schema.Block{
			"exception": schema.SetNestedBlock{
				MarkdownDescription: "A list of exceptions for analytics.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of exception. Valid options are: " + common.FormatOptions(exceptionTypeOptions) + ".",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(exceptionTypeOptions...),
							},
						},
						"value": schema.StringAttribute{
							MarkdownDescription: "The value to match for this exception. Not used when type is `AppSigningInfo`.",
							Optional:            true,
						},
						"app_id": schema.StringAttribute{
							MarkdownDescription: "Application identifier for code signature exceptions.",
							Optional:            true,
						},
						"team_id": schema.StringAttribute{
							MarkdownDescription: "Team identifier for code signature exceptions.",
							Optional:            true,
						},
						"ignore_activity": schema.StringAttribute{
							MarkdownDescription: "The activity type to ignore. Valid values: `Analytics`, `ThreatPrevention`, `TelemetryV2`, `Telemetry`.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("Analytics", "ThreatPrevention", "TelemetryV2", "Telemetry"),
							},
						},
						"analytic_types": schema.SetAttribute{
							MarkdownDescription: "The types of analytics this exception applies to (e.g., `GPFSEvent`, `GPProcessEvent`).",
							Optional:            true,
							ElementType:         types.StringType,
						},
						"analytic_uuid": schema.StringAttribute{
							MarkdownDescription: "The UUID of a specific analytic this exception applies to. Mutually exclusive with `analytic_types`.",
							Optional:            true,
						},
					},
				},
			},
			"endpoint_security_exception": schema.SetNestedBlock{
				MarkdownDescription: "A list of Endpoint Security exceptions.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of endpoint security exception. Valid options are: " + common.FormatOptions(esExceptionTypeOptions) + ".",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(esExceptionTypeOptions...),
							},
						},
						"value": schema.StringAttribute{
							MarkdownDescription: "The value to match for this ES exception. Not used when type is `AppSigningInfo`.",
							Optional:            true,
						},
						"app_id": schema.StringAttribute{
							MarkdownDescription: "Application identifier for code signature exceptions.",
							Optional:            true,
						},
						"team_id": schema.StringAttribute{
							MarkdownDescription: "Team identifier for code signature exceptions.",
							Optional:            true,
						},
						"ignore_activity": schema.StringAttribute{
							MarkdownDescription: "The activity type to ignore. Valid values: `Analytics`, `ThreatPrevention`, `TelemetryV2`, `Telemetry`.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("Analytics", "ThreatPrevention", "TelemetryV2", "Telemetry"),
							},
						},
						"ignore_list_type": schema.StringAttribute{
							MarkdownDescription: "The ignore list type. Valid values: `ignore`, `events`, `sourceIgnore`.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("ignore", "events", "sourceIgnore"),
							},
						},
						"ignore_list_subtype": schema.StringAttribute{
							MarkdownDescription: "The ignore list subtype. Valid values: `parent`, `responsible`, or null.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("parent", "responsible"),
							},
						},
						"event_type": schema.StringAttribute{
							MarkdownDescription: "The endpoint security event type (e.g., `exec`, `open`, `create`).",
							Optional:            true,
						},
					},
				},
			},
		},
	}
}

func (r *ExceptionSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ExceptionSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// IdentitySchema defines the identity attributes for exception set resources.
func (r *ExceptionSetResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the exception set.",
			},
		},
	}
}
