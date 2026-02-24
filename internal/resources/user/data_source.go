package user

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &UsersDataSource{}

// NewUsersDataSource returns a new users data source.
func NewUsersDataSource() datasource.DataSource {
	return &UsersDataSource{}
}

// UsersDataSource lists all users in Jamf Protect.
type UsersDataSource struct {
	service *jamfprotect.Service
}

// UsersDataSourceModel maps the data source schema.
type UsersDataSourceModel struct {
	Users []UserDataSourceItemModel `tfsdk:"users"`
}

// UserDataSourceItemModel maps a single user item (read-only, no timeouts).
type UserDataSourceItemModel struct {
	ID                     types.String `tfsdk:"id"`
	Email                  types.String `tfsdk:"email"`
	IdentityProviderID     types.String `tfsdk:"identity_provider_id"`
	RoleIDs                types.List   `tfsdk:"role_ids"`
	GroupIDs               types.List   `tfsdk:"group_ids"`
	SendEmailNotifications types.Bool   `tfsdk:"send_email_notifications"`
	EmailSeverity          types.String `tfsdk:"email_severity"`
	Created                types.String `tfsdk:"created"`
	Updated                types.String `tfsdk:"updated"`
}

func (d *UsersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

func (d *UsersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all users in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"users": schema.ListNestedAttribute{
				MarkdownDescription: "The list of users.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: userDataSourceAttributes(),
				},
			},
		},
	}
}

func userDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the user.",
			Computed:            true,
		},
		"email": schema.StringAttribute{
			MarkdownDescription: "The email address for the user.",
			Computed:            true,
		},
		"identity_provider_id": schema.StringAttribute{
			MarkdownDescription: "The identity provider identifier for the user.",
			Computed:            true,
		},
		"role_ids": schema.ListAttribute{
			MarkdownDescription: "Role IDs assigned to the user.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"group_ids": schema.ListAttribute{
			MarkdownDescription: "Group IDs assigned to the user.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"send_email_notifications": schema.BoolAttribute{
			MarkdownDescription: "Whether the user receives email notifications.",
			Computed:            true,
		},
		"email_severity": schema.StringAttribute{
			MarkdownDescription: "Minimum severity for email notifications.",
			Computed:            true,
		},
		"created": schema.StringAttribute{
			MarkdownDescription: "The creation timestamp.",
			Computed:            true,
		},
		"updated": schema.StringAttribute{
			MarkdownDescription: "The last-updated timestamp.",
			Computed:            true,
		},
	}
}

func (d *UsersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *UsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data UsersDataSourceModel

	allUsers, err := d.service.ListUsers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing users", err.Error())
		return
	}

	tflog.Trace(ctx, "listed users", map[string]any{"count": len(allUsers)})

	items := make([]UserDataSourceItemModel, 0, len(allUsers))
	for _, api := range allUsers {
		item := userAPIToDataSourceItem(api)
		items = append(items, item)
	}
	data.Users = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
