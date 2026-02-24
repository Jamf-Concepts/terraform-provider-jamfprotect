package change_management

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &ChangeManagementResource{}
var _ resource.ResourceWithImportState = &ChangeManagementResource{}
var _ resource.ResourceWithIdentity = &ChangeManagementResource{}

// changeManagementResourceID is the singleton identifier for change management.
const changeManagementResourceID = "change_management_singleton"

// NewChangeManagementResource returns a new change management resource.
func NewChangeManagementResource() resource.Resource {
	return &ChangeManagementResource{}
}

// ChangeManagementResource manages change management settings in Jamf Protect.
type ChangeManagementResource struct {
	service *jamfprotect.Service
}

func (r *ChangeManagementResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_change_management"
}

func (r *ChangeManagementResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages change management (config freeze) in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The singleton identifier for change management.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"enable_freeze": schema.BoolAttribute{
				MarkdownDescription: "Whether configuration changes are frozen.",
				Required:            true,
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

func (r *ChangeManagementResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing change management by ID.
func (r *ChangeManagementResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// IdentitySchema defines the identity attributes for change management.
func (r *ChangeManagementResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The singleton identifier for change management.",
			},
		},
	}
}
