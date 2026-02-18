// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// exceptionTypeUIToAPI maps UI exception type labels to API values.
var exceptionTypeUIToAPI = map[string]string{
	"App Signing Info": "AppSigningInfo",
	"Team ID":          "TeamId",
	"Process Path":     "Executable",
	"Platform Binary":  "PlatformBinary",
	"User":             "User",
	"File Path":        "Path",
}

// exceptionTypeAPIToUI maps API exception type values to UI labels.
var exceptionTypeAPIToUI = map[string]string{
	"AppSigningInfo": "App Signing Info",
	"TeamId":         "Team ID",
	"Executable":     "Process Path",
	"PlatformBinary": "Platform Binary",
	"User":           "User",
	"Path":           "File Path",
}

// exceptionTypeOptions lists valid UI exception type options.
var exceptionTypeOptions = []string{
	"App Signing Info",
	"Team ID",
	"Process Path",
	"Platform Binary",
	"User",
	"File Path",
}

// esExceptionTypeUIToAPI maps UI endpoint security exception type labels to API values.
var esExceptionTypeUIToAPI = map[string]string{
	"App Signing Info": "AppSigningInfo",
	"Team ID":          "TeamId",
	"Process Path":     "Executable",
	"Platform Binary":  "PlatformBinary",
	"User":             "User",
	"Group":            "Groups",
}

// esExceptionTypeAPIToUI maps API endpoint security exception type values to UI labels.
var esExceptionTypeAPIToUI = map[string]string{
	"AppSigningInfo": "App Signing Info",
	"TeamId":         "Team ID",
	"Executable":     "Process Path",
	"PlatformBinary": "Platform Binary",
	"User":           "User",
	"Groups":         "Group",
}

// esExceptionTypeOptions lists valid UI endpoint security exception type options.
var esExceptionTypeOptions = []string{
	"App Signing Info",
	"Team ID",
	"Process Path",
	"Platform Binary",
	"User",
	"Group",
}

// mapExceptionTypeUIToAPI maps a UI exception type label to an API value.
func mapExceptionTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := exceptionTypeUIToAPI[value]; ok {
		return apiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := exceptionTypeAPIToUI[value]; ok {
		return value
	}
	if _, ok := esExceptionTypeAPIToUI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported exception type",
		fmt.Sprintf("%q is not a supported exception type", value),
	)
	return ""
}

// mapExceptionTypeAPIToUI maps an API exception type value to a UI label.
func mapExceptionTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := exceptionTypeAPIToUI[value]; ok {
		return uiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := exceptionTypeUIToAPI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported exception type",
		fmt.Sprintf("%q is not a supported exception type", value),
	)
	return value
}

// mapEsExceptionTypeUIToAPI maps a UI endpoint security exception type label to an API value.
func mapEsExceptionTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := esExceptionTypeUIToAPI[value]; ok {
		return apiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := esExceptionTypeAPIToUI[value]; ok {
		return value
	}
	if _, ok := exceptionTypeAPIToUI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported endpoint security exception type",
		fmt.Sprintf("%q is not a supported endpoint security exception type", value),
	)
	return ""
}

// mapEsExceptionTypeAPIToUI maps an API endpoint security exception type value to a UI label.
func mapEsExceptionTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := esExceptionTypeAPIToUI[value]; ok {
		return uiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := esExceptionTypeUIToAPI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported endpoint security exception type",
		fmt.Sprintf("%q is not a supported endpoint security exception type", value),
	)
	return value
}
