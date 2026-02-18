// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// ruleTypeUIToAPI maps UI rule type labels to API values for exceptions.
var ruleTypeUIToAPI = map[string]string{
	"App Signing Info": "AppSigningInfo",
	"Team ID":          "TeamId",
	"Process Path":     "Executable",
	"Platform Binary":  "PlatformBinary",
	"User":             "User",
	"File Path":        "Path",
}

// ruleTypeAPIToUI maps API rule type values to UI labels for exceptions.
var ruleTypeAPIToUI = map[string]string{
	"AppSigningInfo": "App Signing Info",
	"TeamId":         "Team ID",
	"Executable":     "Process Path",
	"PlatformBinary": "Platform Binary",
	"User":           "User",
	"Path":           "File Path",
}

// esRuleTypeUIToAPI maps UI rule type labels to API values for ES exceptions.
var esRuleTypeUIToAPI = map[string]string{
	"App Signing Info": "AppSigningInfo",
	"Team ID":          "TeamId",
	"Process Path":     "Executable",
	"Platform Binary":  "PlatformBinary",
	"User":             "User",
	"Group":            "Groups",
}

// esRuleTypeAPIToUI maps API rule type values to UI labels for ES exceptions.
var esRuleTypeAPIToUI = map[string]string{
	"AppSigningInfo": "App Signing Info",
	"TeamId":         "Team ID",
	"Executable":     "Process Path",
	"PlatformBinary": "Platform Binary",
	"User":           "User",
	"Groups":         "Group",
}

// exceptionTypeOptions lists valid UI exception type options.
var exceptionTypeOptions = []string{
	"Override Endpoint Threat Prevention",
	"File System Event",
	"Download Event",
	"Process Event",
	"Screenshot Event",
	"Keylog Register Event",
	"Synthetic Click Event",
	"Ignore for Telemetry",
	"Ignore for Telemetry (Deprecated)",
	"Ignore for Analytic",
}

// exceptionSubTypeOptions lists valid UI subtype options for exception types.
var exceptionSubTypeOptions = map[string][]string{
	"Override Endpoint Threat Prevention": {"Process", "Parent Process", "Responsible Process"},
	"Ignore for Telemetry":                {"Exec Process", "Source Process", "Source Parent Process", "Source Responsible Process"},
}

// ruleTypeOptions lists valid UI rule type options.
var ruleTypeOptions = []string{
	"App Signing Info",
	"Team ID",
	"Process Path",
	"Platform Binary",
	"User",
	"Group",
	"File Path",
}

// exceptionTypeRuleTypeOptions maps exception types to allowed rule types.
var exceptionTypeRuleTypeOptions = map[string][]string{
	"Override Endpoint Threat Prevention": {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User", "Group"},
	"Ignore for Telemetry":                {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User", "Group"},
	"Ignore for Telemetry (Deprecated)":   {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User"},
	"File System Event":                   {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User", "File Path"},
	"Download Event":                      {"File Path"},
	"Process Event":                       {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User"},
	"Screenshot Event":                    {"File Path"},
	"Keylog Register Event":               {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User"},
	"Synthetic Click Event":               {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User"},
	"Ignore for Analytic":                 {"App Signing Info", "Team ID", "Process Path", "Platform Binary", "User"},
}

// analyticTypeToExceptionType maps analytics to UI exception types.
var analyticTypeToExceptionType = map[string]string{
	"GPFSEvent":             "File System Event",
	"GPDownloadEvent":       "Download Event",
	"GPProcessEvent":        "Process Event",
	"GPScreenshotEvent":     "Screenshot Event",
	"GPKeylogRegisterEvent": "Keylog Register Event",
	"GPClickEvent":          "Synthetic Click Event",
}

// exceptionTypeToAnalyticTypes maps UI exception types to analytic types.
var exceptionTypeToAnalyticTypes = map[string][]string{
	"File System Event":     {"GPFSEvent"},
	"Download Event":        {"GPDownloadEvent"},
	"Process Event":         {"GPProcessEvent"},
	"Screenshot Event":      {"GPScreenshotEvent"},
	"Keylog Register Event": {"GPKeylogRegisterEvent"},
	"Synthetic Click Event": {"GPClickEvent"},
}

// mapRuleTypeUIToAPI maps a UI rule type label to an API value.
func mapRuleTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := ruleTypeUIToAPI[value]; ok {
		return apiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := ruleTypeAPIToUI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported rule type",
		fmt.Sprintf("%q is not a supported rule type", value),
	)
	return ""
}

// mapRuleTypeAPIToUI maps an API rule type value to a UI label.
func mapRuleTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := ruleTypeAPIToUI[value]; ok {
		return uiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := ruleTypeUIToAPI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported rule type",
		fmt.Sprintf("%q is not a supported rule type", value),
	)
	return value
}

// mapEsRuleTypeUIToAPI maps a UI ES rule type label to an API value.
func mapEsRuleTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := esRuleTypeUIToAPI[value]; ok {
		return apiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := esRuleTypeAPIToUI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported ES rule type",
		fmt.Sprintf("%q is not a supported ES rule type", value),
	)
	return ""
}

// mapEsRuleTypeAPIToUI maps an API ES rule type value to a UI label.
func mapEsRuleTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := esRuleTypeAPIToUI[value]; ok {
		return uiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := esRuleTypeUIToAPI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported ES rule type",
		fmt.Sprintf("%q is not a supported ES rule type", value),
	)
	return value
}

// isEsExceptionType reports whether the exception type maps to ES exceptions.
func isEsExceptionType(exceptionType string) bool {
	return exceptionType == "Override Endpoint Threat Prevention" || exceptionType == "Ignore for Telemetry"
}

// exceptionTypeRequiresSubType reports whether the exception type requires a subtype.
func exceptionTypeRequiresSubType(exceptionType string) bool {
	return exceptionType == "Ignore for Analytic" || exceptionType == "Override Endpoint Threat Prevention" || exceptionType == "Ignore for Telemetry"
}

// exceptionTypeForbidsSubType reports whether the exception type forbids a subtype.
func exceptionTypeForbidsSubType(exceptionType string) bool {
	return exceptionType == "Ignore for Telemetry (Deprecated)" || analyticTypeToExceptionTypeReverseLookup(exceptionType)
}

// exceptionTypeActivity returns the ignore activity for a UI exception type.
func exceptionTypeActivity(exceptionType string) (string, bool) {
	if exceptionType == "Ignore for Telemetry (Deprecated)" {
		return "Telemetry", true
	}
	if exceptionType == "Ignore for Analytic" {
		return "Analytics", true
	}
	if _, ok := exceptionTypeToAnalyticTypes[exceptionType]; ok {
		return "Analytics", true
	}
	return "", false
}

// exceptionTypeAnalyticTypes returns analytic types for a UI exception type.
func exceptionTypeAnalyticTypes(exceptionType string) ([]string, bool) {
	analyticTypes, ok := exceptionTypeToAnalyticTypes[exceptionType]
	return analyticTypes, ok
}

// mapEsExceptionSubType maps UI ES exception subtypes to API fields.
func mapEsExceptionSubType(exceptionType, subType string) (string, string, string, string, bool) {
	if exceptionType == "Override Endpoint Threat Prevention" {
		ignoreListSubType := ""
		switch subType {
		case "Process":
			ignoreListSubType = ""
		case "Parent Process":
			ignoreListSubType = "parent"
		case "Responsible Process":
			ignoreListSubType = "responsible"
		default:
			return "", "", "", "", false
		}
		return "ThreatPrevention", "ignore", ignoreListSubType, "", true
	}
	if exceptionType == "Ignore for Telemetry" {
		switch subType {
		case "Exec Process":
			return "TelemetryV2", "events", "", "exec", true
		case "Source Process":
			return "TelemetryV2", "sourceIgnore", "", "", true
		case "Source Parent Process":
			return "TelemetryV2", "sourceIgnore", "parent", "", true
		case "Source Responsible Process":
			return "TelemetryV2", "sourceIgnore", "responsible", "", true
		default:
			return "", "", "", "", false
		}
	}
	return "", "", "", "", false
}

// mapApiExceptionType maps API exception fields to UI exception type and subtype.
func mapApiExceptionType(apiIgnoreActivity string, analyticTypes []string, analyticUUID string) (string, string, bool) {
	if apiIgnoreActivity == "Telemetry" {
		return "Ignore for Telemetry (Deprecated)", "", true
	}
	if apiIgnoreActivity == "Analytics" {
		if analyticUUID != "" {
			return "Ignore for Analytic", analyticUUID, true
		}
		if len(analyticTypes) == 1 {
			exceptionType, ok := analyticTypeToExceptionType[analyticTypes[0]]
			return exceptionType, "", ok
		}
	}
	return "", "", false
}

// mapApiEsExceptionType maps API ES exception fields to UI exception type and subtype.
func mapApiEsExceptionType(ignoreActivity, ignoreListType, ignoreListSubType, eventType string) (string, string, bool) {
	if ignoreActivity == "ThreatPrevention" && ignoreListType == "ignore" {
		subType := ""
		switch ignoreListSubType {
		case "":
			subType = "Process"
		case "parent":
			subType = "Parent Process"
		case "responsible":
			subType = "Responsible Process"
		default:
			return "", "", false
		}
		return "Override Endpoint Threat Prevention", subType, true
	}
	if ignoreActivity == "TelemetryV2" {
		if ignoreListType == "events" && eventType == "exec" {
			return "Ignore for Telemetry", "Exec Process", true
		}
		if ignoreListType == "sourceIgnore" {
			subType := ""
			switch ignoreListSubType {
			case "":
				subType = "Source Process"
			case "parent":
				subType = "Source Parent Process"
			case "responsible":
				subType = "Source Responsible Process"
			default:
				return "", "", false
			}
			return "Ignore for Telemetry", subType, true
		}
	}
	return "", "", false
}

// analyticTypeToExceptionTypeReverseLookup reports whether a UI exception type maps to analytic types.
func analyticTypeToExceptionTypeReverseLookup(exceptionType string) bool {
	_, ok := exceptionTypeToAnalyticTypes[exceptionType]
	return ok
}
