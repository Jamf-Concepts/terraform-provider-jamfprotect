// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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

var _ resource.Resource = &PreventListSetResource{}
var _ resource.ResourceWithImportState = &PreventListSetResource{}
var _ resource.ResourceWithIdentity = &PreventListSetResource{}

// NewPreventListSetResource instantiates the prevent list set resource.
func NewPreventListSetResource() resource.Resource {
	return &PreventListSetResource{}
}

// PreventListSetResource manages a Jamf Protect prevent list set.
type PreventListSetResource struct {
	client *jamfprotect.Client
}

// Metadata sets the prevent list set resource type name.
func (r *PreventListSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prevent_list_set"
}

// Schema defines the prevent list set schema.
func (r *PreventListSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a prevent list set in Jamf Protect. Prevent list sets group custom prevent lists and scope them to plans, in the same way analytic sets scope analytics.\n\n" +
			"A custom prevent list reaches an endpoint only when it belongs to a prevent list set that is assigned to that endpoint's plan. Assign prevent list sets to a plan with the `prevent_list_sets` attribute on `jamfprotect_plan`.\n\n" +
			"~> A prevent list set that is assigned to a plan cannot be deleted. Remove it from every plan first, or Terraform will report an error on destroy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the prevent list set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the prevent list set.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the prevent list set.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"prevent_lists": schema.SetAttribute{
				MarkdownDescription: "A set of custom prevent list IDs to include in this prevent list set. An empty set is allowed and ships no prevent lists. Jamf Protect rejects IDs that do not exist.",
				Required:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))},
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

// IdentitySchema defines the identity attributes for prevent list sets.
func (r *PreventListSetResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the prevent list set.",
			},
		},
	}
}

// Configure prepares the prevent list set service client.
func (r *PreventListSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing prevent list sets by ID.
func (r *PreventListSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
