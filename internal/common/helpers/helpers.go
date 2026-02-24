package common

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

// PageInfo represents the pagination metadata returned by list queries.
type PageInfo struct {
	Next  *string `json:"next"`
	Total int     `json:"total"`
}

// ListToStrings converts a types.List of strings into a Go []string.
func ListToStrings(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	if list.IsNull() || list.IsUnknown() {
		return []string{}
	}
	var result []string
	diags.Append(list.ElementsAs(ctx, &result, false)...)
	return result
}

// SetToStrings converts a types.Set of strings into a Go []string.
func SetToStrings(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	if set.IsNull() || set.IsUnknown() {
		return []string{}
	}
	var result []string
	diags.Append(set.ElementsAs(ctx, &result, false)...)
	return result
}

// StringsToList converts a Go []string into a types.List of strings.
func StringsToList(vals []string) types.List {
	if vals == nil {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

// SortedStringsToList copies the given slice, sorts it, and returns a types.List.
func SortedStringsToList(vals []string) types.List {
	sorted := slices.Clone(vals)
	slices.Sort(sorted)
	return StringsToList(sorted)
}

// StringsToSet converts a Go []string into a types.Set of strings.
func StringsToSet(vals []string) types.Set {
	if vals == nil {
		return types.SetValueMust(types.StringType, []attr.Value{})
	}
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}

// IsNotFoundError returns true if the error indicates the resource was not found.
// This is used to make Delete idempotent — if the resource is already gone, the
// delete is considered successful.
func IsNotFoundError(err error) bool {
	return errors.Is(err, client.ErrNotFound)
}

// Int64ValueOrNullValue returns a types.Int64Value if the value is non-zero, or types.Int64Null if the value is zero.
func Int64ValueOrNullValue(value int64) attr.Value {
	if value == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(value)
}

// StringValue returns the string value or empty when null/unknown.
func StringValue(value types.String) string {
	if value.IsNull() || value.IsUnknown() {
		return ""
	}
	return value.ValueString()
}

// StringValueOrNullValue returns a types.StringValue if the value is non-empty, or types.StringNull if the value is empty.
func StringValueOrNullValue(value string) attr.Value {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

// HasStringValue reports whether a string value is set and non-empty.
func HasStringValue(value types.String) bool {
	if value.IsNull() || value.IsUnknown() {
		return false
	}
	return strings.TrimSpace(value.ValueString()) != ""
}

// FormatOptions formats a list of options as a human-readable string for use in schema descriptions.
func FormatOptions(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = "`" + value + "`"
	}
	return strings.Join(quoted, ", ")
}

// EmptyTimeoutsValue returns a correctly typed null timeouts value for resource state.
func EmptyTimeoutsValue() timeouts.Value {
	return timeouts.Value{
		Object: types.ObjectNull(map[string]attr.Type{
			"create": types.StringType,
			"read":   types.StringType,
			"update": types.StringType,
			"delete": types.StringType,
		}),
	}
}

// ResolveTimeouts returns the given timeouts value if it is known, or a
// correctly typed null object if it is null or unknown. This normalizes the
// different timeout handling patterns across resources.
func ResolveTimeouts(t timeouts.Value) timeouts.Value {
	if t.IsNull() || t.IsUnknown() {
		return EmptyTimeoutsValue()
	}
	return t
}

// IsKnownString reports whether a value is set and known.
func IsKnownString(value types.String) bool {
	return !value.IsNull() && !value.IsUnknown()
}

// MapSlice applies fn to each element of items and returns the results.
func MapSlice[T any, R any](items []T, fn func(T) R) []R {
	if len(items) == 0 {
		return nil
	}
	result := make([]R, len(items))
	for i, item := range items {
		result[i] = fn(item)
	}
	return result
}
