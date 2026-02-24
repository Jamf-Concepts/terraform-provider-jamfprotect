package group

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &GroupsDataSource{}

// NewGroupsDataSource returns a new groups data source.
func NewGroupsDataSource() datasource.DataSource {
	return &GroupsDataSource{}
}

// GroupsDataSource lists all groups in Jamf Protect.
type GroupsDataSource struct {
	service *jamfprotect.Service
}

// GroupsDataSourceModel maps the data source schema.
type GroupsDataSourceModel struct {
	Groups []GroupDataSourceItemModel `tfsdk:"groups"`
}

// GroupDataSourceItemModel maps a single group item (read-only, no timeouts).
type GroupDataSourceItemModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	RoleIDs types.List   `tfsdk:"role_ids"`
	Created types.String `tfsdk:"created"`
	Updated types.String `tfsdk:"updated"`
}

func (d *GroupsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_groups"
}

func (d *GroupsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all groups in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"groups": schema.ListNestedAttribute{
				MarkdownDescription: "The list of groups.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: groupDataSourceAttributes(),
				},
			},
		},
	}
}

func groupDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the group.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the group.",
			Computed:            true,
		},
		"role_ids": schema.ListAttribute{
			MarkdownDescription: "Role IDs assigned to the group.",
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

func (d *GroupsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *GroupsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GroupsDataSourceModel

	allGroups, err := d.service.ListGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing groups", err.Error())
		return
	}

	tflog.Trace(ctx, "listed groups", map[string]any{"count": len(allGroups)})

	items := make([]GroupDataSourceItemModel, 0, len(allGroups))
	for _, api := range allGroups {
		item := groupAPIToDataSourceItem(api)
		items = append(items, item)
	}
	data.Groups = items

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
