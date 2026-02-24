package api_client

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &ApiClientsDataSource{}

// NewApiClientsDataSource returns a new API clients data source.
func NewApiClientsDataSource() datasource.DataSource {
	return &ApiClientsDataSource{}
}

// ApiClientsDataSource lists all API clients in Jamf Protect.
type ApiClientsDataSource struct {
	service *jamfprotect.Service
}

// ApiClientsDataSourceModel maps the data source schema.
type ApiClientsDataSourceModel struct {
	ApiClients []ApiClientDataSourceItemModel `tfsdk:"api_clients"`
}

// ApiClientDataSourceItemModel maps a single API client item (read-only, no timeouts).
type ApiClientDataSourceItemModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	RoleIDs  types.List   `tfsdk:"role_ids"`
	Password types.String `tfsdk:"password"`
	Created  types.String `tfsdk:"created"`
}

func (d *ApiClientsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_clients"
}

func (d *ApiClientsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all API clients in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"api_clients": schema.ListNestedAttribute{
				MarkdownDescription: "The list of API clients.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: apiClientDataSourceAttributes(),
				},
			},
		},
	}
}

// apiClientDataSourceAttributes defines the API client attributes for data sources.
func apiClientDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the API client.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the API client.",
			Computed:            true,
		},
		"role_ids": schema.ListAttribute{
			MarkdownDescription: "Role IDs assigned to the API client.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"password": schema.StringAttribute{
			MarkdownDescription: "The API client secret (masked when listed).",
			Computed:            true,
			Sensitive:           true,
		},
		"created": schema.StringAttribute{
			MarkdownDescription: "The creation timestamp.",
			Computed:            true,
		},
	}
}

func (d *ApiClientsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *ApiClientsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ApiClientsDataSourceModel

	items, err := d.service.ListApiClients(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing API clients", err.Error())
		return
	}

	tflog.Trace(ctx, "listed api clients", map[string]any{"count": len(items)})

	apiClients := make([]ApiClientDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := apiClientAPIToDataSourceItem(api)
		apiClients = append(apiClients, item)
	}
	data.ApiClients = apiClients

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
