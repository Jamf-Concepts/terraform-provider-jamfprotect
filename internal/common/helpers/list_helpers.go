package common

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ListConfigModel is the shared configuration model for list resources that
// support name_prefix filtering.
type ListConfigModel struct {
	NamePrefix types.String `tfsdk:"name_prefix"`
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
