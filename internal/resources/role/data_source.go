// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &RolesDataSource{}

// NewRolesDataSource returns a new roles data source.
func NewRolesDataSource() datasource.DataSource {
	return &RolesDataSource{}
}

// RolesDataSource lists all roles in Jamf Protect.
type RolesDataSource struct {
	service *jamfprotect.Service
}

// RolesDataSourceModel maps the data source schema.
type RolesDataSourceModel struct {
	Roles []RoleDataSourceItemModel `tfsdk:"roles"`
}

// RoleDataSourceItemModel maps a single role item (read-only, no timeouts).
type RoleDataSourceItemModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	ReadPermissions  types.Set    `tfsdk:"read_permissions"`
	WritePermissions types.Set    `tfsdk:"write_permissions"`
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
		"read_permissions": schema.SetAttribute{
			MarkdownDescription: "Read permissions assigned to the role.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"write_permissions": schema.SetAttribute{
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
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	d.service = jamfprotect.NewService(client)
}

func (d *RolesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RolesDataSourceModel

	items, err := d.service.ListRoles(ctx)
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
