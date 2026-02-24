// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package downloads

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// installerPackageAttrTypes defines the attribute types for installer_package.
var installerPackageAttrTypes = map[string]attr.Type{
	"installer_url":   types.StringType,
	"uninstaller_url": types.StringType,
	"version":         types.StringType,
}
