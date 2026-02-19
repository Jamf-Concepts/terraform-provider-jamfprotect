// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &UserResource{}
var _ resource.ResourceWithImportState = &UserResource{}
var _ resource.ResourceWithIdentity = &UserResource{}
var _ resource.ResourceWithValidateConfig = &UserResource{}

// NewUserResource returns a new user resource.
func NewUserResource() resource.Resource {
	return &UserResource{}
}

// UserResource manages a Jamf Protect user.
type UserResource struct {
	service *jamfprotect.Service
}

func (r *UserResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *UserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a user in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the user.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"email": schema.StringAttribute{
				MarkdownDescription: "The email address for the user.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"identity_provider_id": schema.StringAttribute{
				MarkdownDescription: "Optional identity provider identifier. Use `1` for local Jamf Protect users and `2` for the first external identity provider and so on. If unset, the user can only receive email notifications.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role_ids": schema.SetAttribute{
				MarkdownDescription: "Role IDs assigned to the user. Use `1` for the Read Only role, `2` for the Full Admin role, or other role IDs as needed. Only applicable for users with an identity provider.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("identity_provider_id"))},
			},
			"group_ids": schema.SetAttribute{
				MarkdownDescription: "Group IDs assigned to the user. Use `1` for the default group or other group IDs as needed. Only applicable for users with an identity provider.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("identity_provider_id"))},
			},
			"send_email_notifications": schema.BoolAttribute{
				MarkdownDescription: "Whether the user receives email notifications.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"email_severity": schema.StringAttribute{
				MarkdownDescription: "Minimum severity for email notifications. Valid options are: " + common.FormatOptions(emailSeverityOptions) + ".",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Low"),
				Validators: []validator.String{
					stringvalidator.OneOf(emailSeverityOptions...),
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

func (r *UserResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *UserResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !data.IdentityProviderID.IsNull() && !data.IdentityProviderID.IsUnknown() {
		return
	}

	roleIDs := common.SetToStrings(ctx, data.RoleIDs, &resp.Diagnostics)
	groupIDs := common.SetToStrings(ctx, data.GroupIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(roleIDs) > 0 || len(groupIDs) > 0 {
		resp.Diagnostics.AddError(
			"Invalid role/group assignment",
			"role_ids and group_ids require identity_provider_id to be set.",
		)
	}
}

// ImportState supports importing users by ID.
func (r *UserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// IdentitySchema defines the identity attributes for user resources.
func (r *UserResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the user.",
			},
		},
	}
}
