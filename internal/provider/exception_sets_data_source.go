// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

var _ datasource.DataSource = &ExceptionSetsDataSource{}

func NewExceptionSetsDataSource() datasource.DataSource {
	return &ExceptionSetsDataSource{}
}

// ExceptionSetsDataSource lists all exception sets in Jamf Protect.
type ExceptionSetsDataSource struct {
	client *client.Client
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
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *ExceptionSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ExceptionSetsDataSourceModel

	// Fetch all exception sets with pagination.
	var allItems []exceptionSetAPIModel
	var nextToken *string

	for {
		vars := map[string]any{}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListExceptionSets struct {
				Items    []exceptionSetAPIModel `json:"items"`
				PageInfo pageInfo               `json:"pageInfo"`
			} `json:"listExceptionSets"`
		}
		if err := d.client.Query(ctx, listExceptionSetsQuery, vars, &result); err != nil {
			resp.Diagnostics.AddError("Error listing exception sets", err.Error())
			return
		}

		allItems = append(allItems, result.ListExceptionSets.Items...)

		if result.ListExceptionSets.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListExceptionSets.PageInfo.Next
	}

	tflog.Trace(ctx, "listed exception sets", map[string]any{"count": len(allItems)})

	exceptionSets := make([]ExceptionSetDataSourceItemModel, 0, len(allItems))
	for _, api := range allItems {
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

// exceptionSetAPIModel matches the GraphQL response structure.
type exceptionSetAPIModel struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

const listExceptionSetsQuery = `
query listExceptionSets($nextToken: String, $direction: OrderDirection = DESC, $field: ExceptionSetOrderField = created) {
  listExceptionSets(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      uuid
      name
      managed
    }
    pageInfo {
      next
      total
    }
  }
}
`
