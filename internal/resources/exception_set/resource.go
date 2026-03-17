// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

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

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
)

var _ resource.Resource = &ExceptionSetResource{}
var _ resource.ResourceWithImportState = &ExceptionSetResource{}
var _ resource.ResourceWithIdentity = &ExceptionSetResource{}
var _ resource.ResourceWithValidateConfig = &ExceptionSetResource{}
var _ resource.ResourceWithModifyPlan = &ExceptionSetResource{}

func NewExceptionSetResource() resource.Resource {
	return &ExceptionSetResource{}
}

// ExceptionSetResource manages a Jamf Protect exception set.
type ExceptionSetResource struct {
	client *jamfprotect.Client
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
				Validators:          []validator.String{validators.ResourceName()},
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
			"exceptions": schema.SetNestedAttribute{
				MarkdownDescription: "Exception entries aligned with UI type, subtype, and rules.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The UI exception type. Valid options are: " + common.FormatOptions(exceptionTypeOptions) + ".",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(exceptionTypeOptions...),
							},
						},
						"sub_type": schema.StringAttribute{
							MarkdownDescription: "The UI subtype associated with the exception type. Required for some types.",
							Optional:            true,
						},
						"rules": schema.ListNestedAttribute{
							MarkdownDescription: "Rules applied to the exception type and subtype.",
							Required:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"rule_type": schema.StringAttribute{
										MarkdownDescription: "The rule type. Valid options are: " + common.FormatOptions(ruleTypeOptions) + ".",
										Required:            true,
										Validators: []validator.String{
											stringvalidator.OneOf(ruleTypeOptions...),
										},
									},
									"value": schema.StringAttribute{
										MarkdownDescription: "The value for rules that accept a single string.",
										Optional:            true,
									},
									"app_id": schema.StringAttribute{
										MarkdownDescription: "Application identifier for App Signing Info rules.",
										Optional:            true,
									},
									"team_id": schema.StringAttribute{
										MarkdownDescription: "Team identifier for App Signing Info rules.",
										Optional:            true,
									},
								},
							},
						},
					},
				},
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
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
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
