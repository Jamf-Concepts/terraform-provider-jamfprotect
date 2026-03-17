// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ datasource.DataSource = &RolesDataSource{}

// NewRolesDataSource returns a new roles data source.
func NewRolesDataSource() datasource.DataSource {
	return &RolesDataSource{}
}

// RolesDataSource lists all roles in Jamf Protect.
type RolesDataSource struct {
	client *jamfprotect.Client
}

// RolesDataSourceModel maps the data source schema.
type RolesDataSourceModel struct {
	Roles []RoleDataSourceItemModel `tfsdk:"roles"`
}

// RoleDataSourceItemModel maps a single role item (read-only, no timeouts).
type RoleDataSourceItemModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	ReadPermissions  types.List   `tfsdk:"read_permissions"`
	WritePermissions types.List   `tfsdk:"write_permissions"`
	Created          types.String `tfsdk:"created"`
	Updated          types.String `tfsdk:"updated"`
}

func (d *RolesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roles"
}

func (d *RolesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all roles in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"roles": schema.ListNestedAttribute{
				MarkdownDescription: "The list of roles.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: roleDataSourceAttributes(),
				},
			},
		},
	}
}

// roleDataSourceAttributes defines the role attributes for data sources.
func roleDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the role.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the role.",
			Computed:            true,
		},
		"read_permissions": schema.ListAttribute{
			MarkdownDescription: "Read permissions assigned to the role.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"write_permissions": schema.ListAttribute{
			MarkdownDescription: "Write permissions assigned to the role.",
			Computed:            true,
			ElementType:         types.StringType,
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

func (d *RolesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

func (d *RolesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RolesDataSourceModel

	items, err := d.client.ListRoles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing roles", err.Error())
		return
	}

	tflog.Trace(ctx, "listed roles", map[string]any{"count": len(items)})

	roles := make([]RoleDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := roleAPIToDataSourceItem(api)
		roles = append(roles, item)
	}
	data.Roles = roles

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
