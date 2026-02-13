// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

// listToStrings converts a types.List of strings into a Go []string.
func listToStrings(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	if list.IsNull() || list.IsUnknown() {
		return []string{}
	}
	var result []string
	diags.Append(list.ElementsAs(ctx, &result, false)...)
	return result
}

// stringsToList converts a Go []string into a types.List of strings.
func stringsToList(vals []string) types.List {
	if vals == nil {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

// isNotFoundError returns true if the error indicates the resource was not found.
// This is used to make Delete idempotent — if the resource is already gone, the
// delete is considered successful.
func isNotFoundError(err error) bool {
	return errors.Is(err, graphql.ErrNotFound)
}

// pageInfo represents the pagination metadata returned by list queries.
type pageInfo struct {
	Next  *string `json:"next"`
	Total int     `json:"total"`
}
