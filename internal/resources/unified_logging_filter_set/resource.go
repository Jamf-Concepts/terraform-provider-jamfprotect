// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
)

var _ resource.Resource = &UnifiedLoggingFilterSetResource{}
var _ resource.ResourceWithImportState = &UnifiedLoggingFilterSetResource{}
var _ resource.ResourceWithIdentity = &UnifiedLoggingFilterSetResource{}
var _ resource.ResourceWithModifyPlan = &UnifiedLoggingFilterSetResource{}

// NewUnifiedLoggingFilterSetResource instantiates the unified logging filter set resource.
func NewUnifiedLoggingFilterSetResource() resource.Resource {
	return &UnifiedLoggingFilterSetResource{}
}

// UnifiedLoggingFilterSetResource manages a Jamf Protect unified logging filter set.
type UnifiedLoggingFilterSetResource struct {
	client *jamfprotect.Client
}

// Metadata sets the unified logging filter set resource type name.
func (r *UnifiedLoggingFilterSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter_set"
}

// Schema defines the unified logging filter set schema.
func (r *UnifiedLoggingFilterSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a unified logging filter set in Jamf Protect. Filter sets group unified logging filters and scope them to plans, in the same way analytic sets scope analytics.\n\n" +
			"A filter reaches an endpoint only when it belongs to a filter set that is assigned to that endpoint's plan. Assign filter sets to a plan with the `unified_logging_filter_sets` attribute on `jamfprotect_plan`.\n\n" +
			"~> A filter set that is assigned to a plan cannot be deleted. Remove it from every plan first, or Terraform will report an error on destroy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the unified logging filter set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the unified logging filter set.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the unified logging filter set.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"filters": schema.SetAttribute{
				MarkdownDescription: "A set of unified logging filter UUIDs to include in this filter set. An empty set is allowed and ships no filters.",
				Required:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(validators.UUID())},
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
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

// IdentitySchema defines the identity attributes for unified logging filter sets.
func (r *UnifiedLoggingFilterSetResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the unified logging filter set.",
			},
		},
	}
}

// Configure prepares the unified logging filter set service client.
func (r *UnifiedLoggingFilterSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing unified logging filter sets by ID.
func (r *UnifiedLoggingFilterSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
