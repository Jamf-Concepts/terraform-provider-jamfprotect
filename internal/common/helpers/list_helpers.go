// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ListConfigModel is the shared configuration model for list resources that
// support name_prefix filtering and, for resource types that have Jamf-provided
// built-in / system instances, an opt-in exclude_builtins toggle.
type ListConfigModel struct {
	NamePrefix      types.String `tfsdk:"name_prefix"`
	ExcludeBuiltins types.Bool   `tfsdk:"exclude_builtins"`
}

// ValidateNamePrefix checks that name_prefix is not empty when set.
func ValidateNamePrefix(config ListConfigModel, diags *diag.Diagnostics) {
	if !config.NamePrefix.IsNull() && !config.NamePrefix.IsUnknown() && strings.TrimSpace(config.NamePrefix.ValueString()) == "" {
		diags.AddError(
			"Invalid name_prefix",
			"name_prefix must not be empty when set.",
		)
	}
}

// NamePrefixSchemaAttribute returns the shared name_prefix schema attribute
// used by all list resources.
func NamePrefixSchemaAttribute() listschema.StringAttribute {
	return listschema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Optional name prefix filter.",
	}
}

// ExcludeBuiltinsSchemaAttribute returns the shared exclude_builtins schema
// attribute, used by list resources whose type has Jamf-provided built-in /
// system instances.
func ExcludeBuiltinsSchemaAttribute() listschema.BoolAttribute {
	return listschema.BoolAttribute{
		Optional: true,
		MarkdownDescription: "When true, Jamf-provided built-in / system instances are excluded from the " +
			"results. Defaults to false — all instances, including built-ins, are returned.",
	}
}

// ExcludeBuiltins reports whether built-in / system instances should be excluded
// from list results. Defaults to false (return everything) unless explicitly set.
func ExcludeBuiltins(config ListConfigModel) bool {
	return !config.ExcludeBuiltins.IsNull() && !config.ExcludeBuiltins.IsUnknown() && config.ExcludeBuiltins.ValueBool()
}

// MatchesNamePrefix reports whether the given name matches the prefix in the
// list configuration. Returns true if no prefix is configured.
func MatchesNamePrefix(config ListConfigModel, name string) bool {
	if config.NamePrefix.IsNull() || config.NamePrefix.IsUnknown() {
		return true
	}
	prefix := config.NamePrefix.ValueString()
	if prefix == "" {
		return true
	}
	return strings.HasPrefix(name, prefix)
}
