// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ resource.Resource = &DataForwardingResource{}
var _ resource.ResourceWithImportState = &DataForwardingResource{}
var _ resource.ResourceWithIdentity = &DataForwardingResource{}

// dataForwardingResourceID is the singleton identifier for data forwarding.
const dataForwardingResourceID = "data_forwarding_singleton"

var dataCollectionEndpointPattern = regexp.MustCompile(`^.*\.azure\.(com|us|cn|de)$`)

// NewDataForwardingResource returns a new data forwarding resource.
func NewDataForwardingResource() resource.Resource {
	return &DataForwardingResource{}
}

// DataForwardingResource manages data forwarding settings in Jamf Protect.
type DataForwardingResource struct {
	client *jamfprotect.Client
}

func (r *DataForwardingResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_data_forwarding"
}

func (r *DataForwardingResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages data forwarding settings in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The singleton identifier for data forwarding.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"amazon_s3": schema.SingleNestedAttribute{
				MarkdownDescription: "Amazon S3 forwarding settings.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						MarkdownDescription: "Whether Amazon S3 forwarding is enabled.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"encrypt_forwarding_data": schema.BoolAttribute{
						MarkdownDescription: "Whether forwarded data is encrypted.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(true),
					},
					"bucket_name": schema.StringAttribute{
						MarkdownDescription: "The Amazon S3 bucket name.",
						Required:            true,
					},
					"prefix": schema.StringAttribute{
						MarkdownDescription: "The prefix for Jamf Protect data objects in the bucket.",
						Required:            true,
					},
					"iam_role": schema.StringAttribute{
						MarkdownDescription: "The IAM role ARN assumed by Jamf Protect.",
						Optional:            true,
						Computed:            true,
					},
					"cloudformation_template": schema.StringAttribute{
						MarkdownDescription: "The CloudFormation template for setting up S3 forwarding.",
						Computed:            true,
						PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"external_id": schema.StringAttribute{
						MarkdownDescription: "The external ID for the IAM role trust policy, derived from the organization UUID.",
						Computed:            true,
						PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
				},
			},
			"microsoft_sentinel": schema.SingleNestedAttribute{
				MarkdownDescription: "Microsoft Sentinel (DCR) forwarding settings.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						MarkdownDescription: "Whether Microsoft Sentinel forwarding is enabled.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"secret_exists": schema.BoolAttribute{
						MarkdownDescription: "Whether an application secret is configured.",
						Computed:            true,
						PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					"directory_id": schema.StringAttribute{
						MarkdownDescription: "The Azure tenant ID.",
						Required:            true,
					},
					"application_id": schema.StringAttribute{
						MarkdownDescription: "The Azure client ID.",
						Required:            true,
					},
					"data_collection_endpoint": schema.StringAttribute{
						MarkdownDescription: "The data collection endpoint (must end with .azure.com, .azure.us, .azure.cn, or .azure.de).",
						Required:            true,
						Validators: []validator.String{
							stringvalidator.RegexMatches(dataCollectionEndpointPattern, "must match ^.*\\.azure\\.(com|us|cn|de)$"),
						},
					},
					"application_secret_value": schema.StringAttribute{
						MarkdownDescription: "The Azure client secret value. Only sent on update.\n\n" +
							"~> **Deprecated (2026-06-17):** this attribute stores the secret in plaintext in Terraform " +
							"state. Use `application_secret_value_wo` together with `application_secret_value_wo_version` " +
							"instead; the write-only attribute is never persisted to state.",
						DeprecationMessage: "Deprecated as of 2026-06-17. Use application_secret_value_wo together with " +
							"application_secret_value_wo_version instead; this attribute stores the secret in plaintext " +
							"in Terraform state, whereas the write-only attribute is not persisted to state.",
						Optional:  true,
						Sensitive: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("application_secret_value_wo")),
						},
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"application_secret_value_wo": schema.StringAttribute{
						MarkdownDescription: "The Azure client secret value, supplied as a " +
							"[write-only attribute](https://developer.hashicorp.com/terraform/language/resources/ephemeral#write-only-arguments) " +
							"(Terraform 1.11+). The value is sent to Jamf Protect but never stored in Terraform state. " +
							"Requires `application_secret_value_wo_version`; rotate the secret by changing that version. " +
							"Conflicts with the deprecated `application_secret_value`.",
						Optional:  true,
						Sensitive: true,
						WriteOnly: true,
						Validators: []validator.String{
							stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("application_secret_value_wo_version")),
						},
					},
					"application_secret_value_wo_version": schema.StringAttribute{
						MarkdownDescription: "Version identifier for `application_secret_value_wo`. Change this value " +
							"(for example to a new timestamp) to push a rotated secret, since the write-only value " +
							"itself is not tracked in state. Required when `application_secret_value_wo` is set.",
						Optional: true,
						Validators: []validator.String{
							stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("application_secret_value_wo")),
						},
					},
					"alerts":               dataStreamSchema("Alerts forwarding settings."),
					"unified_logs":         dataStreamSchema("Unified logs forwarding settings."),
					"telemetry_deprecated": dataStreamSchema("Telemetry (deprecated) forwarding settings."),
					"telemetry":            dataStreamSchema("Telemetry forwarding settings."),
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

// dataStreamSchema returns the nested schema for a data stream.
func dataStreamSchema(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: description,
		Required:            true,
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the data stream is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"data_collection_rule_immutable_id": schema.StringAttribute{
				MarkdownDescription: "The data collection rule immutable ID.",
				Optional:            true,
			},
			"stream_name": schema.StringAttribute{
				MarkdownDescription: "The stream name in the data collection rule.",
				Optional:            true,
			},
		},
	}
}

func (r *DataForwardingResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing data forwarding by ID.
func (r *DataForwardingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// IdentitySchema defines the identity attributes for data forwarding.
func (r *DataForwardingResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The singleton identifier for data forwarding.",
			},
		},
	}
}
