package removable_storage_control_set

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &RemovableStorageControlSetResource{}
var _ resource.ResourceWithImportState = &RemovableStorageControlSetResource{}
var _ resource.ResourceWithIdentity = &RemovableStorageControlSetResource{}

// NewRemovableStorageControlSetResource returns a new removable storage control set resource.
func NewRemovableStorageControlSetResource() resource.Resource {
	return &RemovableStorageControlSetResource{}
}

// RemovableStorageControlSetResource manages a Jamf Protect removable storage control set.
type RemovableStorageControlSetResource struct {
	service *jamfprotect.Service
}

func (r *RemovableStorageControlSetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_removable_storage_control_set"
}

// Schema defines the removable storage control set schema.
func (r *RemovableStorageControlSetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	permissionValidator := stringvalidator.OneOf(permissionUIOptions...)
	permissionDesc := "The permission for matching devices. Valid options are: " + common.FormatOptions(permissionUIOptions) + "."
	vendorIDPattern := regexp.MustCompile("^0x[0-9A-Fa-f]{4}$")
	vendorIDValidator := stringvalidator.RegexMatches(vendorIDPattern, "must be in the form 0x0000")

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a removable storage control set in Jamf Protect. Removable storage control sets define policies for removable storage device access, including default permissions and device-specific overrides for encrypted devices, vendors, serial numbers, and product IDs.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the removable storage control set.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the removable storage control set.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the removable storage control set.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"default_permission": schema.StringAttribute{
				MarkdownDescription: "The default permission for removable storage devices. Valid options are: " + common.FormatOptions(permissionUIOptions) + ".",
				Required:            true,
				Validators:          []validator.String{permissionValidator},
			},
			"default_local_notification_message": schema.StringAttribute{
				MarkdownDescription: "The default local notification message displayed to users when a removable storage device action is triggered.",
				Optional:            true,
				Computed:            true,
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
			"override_encrypted_devices": schema.ListNestedAttribute{
				MarkdownDescription: "Overrides applied to encrypted devices.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: permissionDesc,
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
					},
				},
			},
			"override_vendor_id": schema.ListNestedAttribute{
				MarkdownDescription: "Overrides applied to vendor IDs.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: permissionDesc,
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"vendor_ids": schema.ListAttribute{
							MarkdownDescription: "A list of vendor IDs that this override applies to. IDs must match the format `0x0000`.",
							Required:            true,
							ElementType:         types.StringType,
							Validators: []validator.List{
								listvalidator.ValueStringsAre(vendorIDValidator),
							},
						},
					},
				},
			},
			"override_product_id": schema.ListNestedAttribute{
				MarkdownDescription: "Overrides applied to product IDs.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: permissionDesc,
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"product_id": schema.ListNestedAttribute{
							MarkdownDescription: "Vendor and product IDs that this override applies to. IDs must match the format `0x0000`.",
							Required:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"vendor_id": schema.StringAttribute{
										MarkdownDescription: "The vendor ID.",
										Required:            true,
										Validators:          []validator.String{vendorIDValidator},
									},
									"product_id": schema.StringAttribute{
										MarkdownDescription: "The product ID.",
										Required:            true,
										Validators:          []validator.String{vendorIDValidator},
									},
								},
							},
						},
					},
				},
			},
			"override_serial_number": schema.ListNestedAttribute{
				MarkdownDescription: "Overrides applied to serial numbers.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"permission": schema.StringAttribute{
							MarkdownDescription: permissionDesc,
							Required:            true,
							Validators:          []validator.String{permissionValidator},
						},
						"local_notification_message": schema.StringAttribute{
							MarkdownDescription: "The local notification message displayed to users when this override is triggered.",
							Optional:            true,
							Computed:            true,
						},
						"apply_to": schema.StringAttribute{
							MarkdownDescription: "Specifies which device categories the override applies to.",
							Optional:            true,
							Computed:            true,
						},
						"serial_numbers": schema.ListAttribute{
							MarkdownDescription: "A list of serial numbers that this override applies to.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
		},
	}
}

// IdentitySchema defines the identity attributes for removable storage control sets.
func (r *RemovableStorageControlSetResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the removable storage control set.",
			},
		},
	}
}

// Configure prepares the removable storage control set service client.
func (r *RemovableStorageControlSetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing removable storage control sets by ID.
func (r *RemovableStorageControlSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
