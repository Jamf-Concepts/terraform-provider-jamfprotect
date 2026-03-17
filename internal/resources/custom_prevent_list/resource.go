// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"context"

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

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
)

var _ resource.Resource = &CustomPreventListResource{}
var _ resource.ResourceWithImportState = &CustomPreventListResource{}
var _ resource.ResourceWithIdentity = &CustomPreventListResource{}

func NewCustomPreventListResource() resource.Resource {
	return &CustomPreventListResource{}
}

// CustomPreventListResource manages a Jamf Protect prevent list (threat prevention allow/block list).
type CustomPreventListResource struct {
	client *jamfprotect.Client
}

func (r *CustomPreventListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_prevent_list"
}

func (r *CustomPreventListResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a custom prevent list in Jamf Protect. Custom prevent lists allow you to define allow/block entries by Team ID, file hash, CDHash, or signing ID for threat prevention.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the prevent list.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the custom prevent list.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the custom prevent list.",
				Optional:            true,
				Computed:            true,
			},
			"prevent_type": schema.StringAttribute{
				MarkdownDescription: "The type of custom prevent list. Valid options are: " + common.FormatOptions(preventTypeOptions) + ".",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf(preventTypeOptions...),
				},
			},
			"list_data": schema.ListAttribute{
				MarkdownDescription: "The list of entries (identifiers) in the custom prevent list.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"entry_count": schema.Int64Attribute{
				MarkdownDescription: "The number of entries in the custom prevent list.",
				Computed:            true,
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

func (r *CustomPreventListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

func (r *CustomPreventListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *CustomPreventListResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the prevent list.",
			},
		},
	}
}
