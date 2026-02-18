// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// sensorTypeUIToAPI is a mapping of user-friendly sensor type names to the corresponding API values.
var sensorTypeUIToAPI = map[string]string{
	"File System Event":          "GPFSEvent",
	"Download Event":             "GPDownloadEvent",
	"Process Event":              "GPProcessEvent",
	"Screenshot Event":           "GPScreenshotEvent",
	"Keylog Register Event":      "GPKeylogRegisterEvent",
	"Synthetic Click Event":      "GPClickEvent",
	"Malware Removal Tool Event": "GPMRTEvent",
	"USB Event":                  "GPUSBEvent",
	"Gatekeeper Event":           "GPGatekeeperEvent",
}

// sensorTypeAPIToUI is a mapping of API sensor type values to user-friendly names for display in Terraform.
var sensorTypeAPIToUI = map[string]string{
	"GPFSEvent":             "File System Event",
	"GPDownloadEvent":       "Download Event",
	"GPProcessEvent":        "Process Event",
	"GPScreenshotEvent":     "Screenshot Event",
	"GPKeylogRegisterEvent": "Keylog Register Event",
	"GPClickEvent":          "Synthetic Click Event",
	"GPMRTEvent":            "Malware Removal Tool Event",
	"GPUSBEvent":            "USB Event",
	"GPGatekeeperEvent":     "Gatekeeper Event",
}

// sensorTypeOptions is a list of valid sensor type options for validation and display purposes.
var sensorTypeOptions = []string{
	"File System Event",
	"Download Event",
	"Process Event",
	"Screenshot Event",
	"Keylog Register Event",
	"Synthetic Click Event",
	"Malware Removal Tool Event",
	"USB Event",
	"Gatekeeper Event",
}

// severityOptions is a list of valid severity options for validation and display purposes.
var severityOptions = []string{
	"High",
	"Medium",
	"Low",
	"Informational",
}

// mapSensorTypeUIToAPI maps a user-friendly sensor type name to the corresponding API value. If the provided value is not valid,
func mapSensorTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := sensorTypeUIToAPI[value]; ok {
		return apiValue
	}
	diags.AddError(
		"Unsupported sensor type",
		fmt.Sprintf("%q is not a supported sensor type", value),
	)
	return ""
}

// mapSensorTypeAPIToUI maps an API sensor type value to a user-friendly name for display in Terraform. If the provided value is not recognized,
func mapSensorTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := sensorTypeAPIToUI[value]; ok {
		return uiValue
	}
	diags.AddError(
		"Unsupported sensor type",
		fmt.Sprintf("%q is not a supported sensor type", value),
	)
	return value
}

// normalizeFilterValue normalizes the filter value by replacing double backslashes with single backslashes, which is necessary to handle Terraform's escaping of backslashes in strings. If the value is empty, it returns it as-is.
func normalizeFilterValue(value string) string {
	if value == "" {
		return value
	}
	return strings.ReplaceAll(value, "\\\\", "\\")
}
