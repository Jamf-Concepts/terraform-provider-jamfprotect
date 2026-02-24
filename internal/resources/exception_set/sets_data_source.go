// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &ExceptionSetsDataSource{}

func NewExceptionSetsDataSource() datasource.DataSource {
	return &ExceptionSetsDataSource{}
}

// ExceptionSetsDataSource lists all exception sets in Jamf Protect.
type ExceptionSetsDataSource struct {
	service *jamfprotect.Service
}

// ExceptionSetsDataSourceModel maps the data source schema.
type ExceptionSetsDataSourceModel struct {
	ExceptionSets []ExceptionSetDataSourceItemModel `tfsdk:"exception_sets"`
}

// ExceptionSetDataSourceItemModel maps a single exception set item.
type ExceptionSetDataSourceItemModel struct {
	UUID    types.String `tfsdk:"uuid"`
	Name    types.String `tfsdk:"name"`
	Managed types.Bool   `tfsdk:"managed"`
}

func (d *ExceptionSetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_exception_sets"
}

func (d *ExceptionSetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all exception sets in Jamf Protect. Exception sets define exceptions to analytics and can be associated with plans.",
		Attributes: map[string]schema.Attribute{
			"exception_sets": schema.ListNestedAttribute{
				MarkdownDescription: "The list of exception sets.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: exceptionSetDataSourceAttributes(),
				},
			},
		},
	}
}

func exceptionSetDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"uuid": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the exception set.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the exception set.",
			Computed:            true,
		},
		"managed": schema.BoolAttribute{
			MarkdownDescription: "Whether this is a Jamf-managed exception set.",
			Computed:            true,
		},
	}
}

func (d *ExceptionSetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (d *ExceptionSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ExceptionSetsDataSourceModel

	items, err := d.service.ListExceptionSets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing exception sets", err.Error())
		return
	}

	tflog.Trace(ctx, "listed exception sets", map[string]any{"count": len(items)})

	exceptionSets := make([]ExceptionSetDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := ExceptionSetDataSourceItemModel{
			UUID:    types.StringValue(api.UUID),
			Name:    types.StringValue(api.Name),
			Managed: types.BoolValue(api.Managed),
		}
		exceptionSets = append(exceptionSets, item)
	}
	data.ExceptionSets = exceptionSets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
