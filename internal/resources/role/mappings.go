// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// rolePermissionLabelToAPI maps friendly permission names to API values.
var rolePermissionLabelToAPI = map[string]string{
	"all":                            "all",
	"All":                            "all",
	"Account Groups & Mappings":      "Group",
	"Account Identity Providers":     "Connection",
	"Account Roles":                  "Role",
	"Account Users":                  "User",
	"Actions":                        "ActionConfigs",
	"Alerts":                         "Alert",
	"Analytic Sets":                  "AnalyticSet",
	"Analytics":                      "Analytic",
	"API Clients":                    "ApiClient",
	"Change Management":              "ConfigFreeze",
	"Compliance":                     "Insight",
	"Computers":                      "Computer",
	"Data Forwarding":                "DataForward",
	"Data Retention":                 "DataRetention",
	"Downloads":                      "Download",
	"Exception Sets":                 "ExceptionSet",
	"Plans":                          "Plan",
	"Prevent Lists":                  "PreventList",
	"Removable Storage Control Sets": "USBControlSet",
	"Telemetry":                      "Telemetry",
	"Unified Logging":                "UnifiedLoggingFilter",
	"Account Information":            "Organization",
	"Audit Logs":                     "AuditLog",
	"Endpoint Threat Prevention":     "ThreatPreventionVersion",
}

// rolePermissionAPIToLabel maps API permission values to friendly names.
var rolePermissionAPIToLabel = map[string]string{
	"all":                     "all",
	"Group":                   "Account Groups & Mappings",
	"Connection":              "Account Identity Providers",
	"Role":                    "Account Roles",
	"User":                    "Account Users",
	"ActionConfigs":           "Actions",
	"Alert":                   "Alerts",
	"AnalyticSet":             "Analytic Sets",
	"Analytic":                "Analytics",
	"ApiClient":               "API Clients",
	"ConfigFreeze":            "Change Management",
	"Insight":                 "Compliance",
	"Computer":                "Computers",
	"DataForward":             "Data Forwarding",
	"DataRetention":           "Data Retention",
	"Download":                "Downloads",
	"ExceptionSet":            "Exception Sets",
	"Plan":                    "Plans",
	"PreventList":             "Prevent Lists",
	"USBControlSet":           "Removable Storage Control Sets",
	"Telemetry":               "Telemetry",
	"UnifiedLoggingFilter":    "Unified Logging",
	"Organization":            "Account Information",
	"AuditLog":                "Audit Logs",
	"ThreatPreventionVersion": "Endpoint Threat Prevention",
}

// rolePermissionDependencies defines read dependencies between permissions.
var rolePermissionDependencies = map[string][]string{
	"AnalyticSet":   {"Analytic"},
	"ConfigFreeze":  {"Organization"},
	"DataRetention": {"Organization"},
	"DataForward":   {"Organization"},
}

// rolePermissionWriteOptions lists all available write permission options for documentation.
var rolePermissionWriteOptions = []string{
	"All",
	"Account Groups & Mappings",
	"Account Identity Providers",
	"Account Roles",
	"Account Users",
	"Actions",
	"Alerts",
	"Analytic Sets",
	"Analytics",
	"API Clients",
	"Change Management",
	"Compliance",
	"Computers",
	"Data Forwarding",
	"Data Retention",
	"Downloads",
	"Exception Sets",
	"Plans",
	"Prevent Lists",
	"Removable Storage Control Sets",
	"Telemetry",
	"Unified Logging",
}

// rolePermissionReadOptions lists all available read permission options for documentation.
var rolePermissionReadOptions = []string{
	"All",
	"Account Groups & Mappings",
	"Account Identity Providers",
	"Account Roles",
	"Account Users",
	"Actions",
	"Alerts",
	"Analytic Sets",
	"Analytics",
	"API Clients",
	"Change Management",
	"Compliance",
	"Computers",
	"Data Forwarding",
	"Data Retention",
	"Downloads",
	"Exception Sets",
	"Plans",
	"Prevent Lists",
	"Removable Storage Control Sets",
	"Telemetry",
	"Unified Logging",
	"Account Information",
	"Audit Logs",
	"Endpoint Threat Prevention",
}

// rolePermissionAPIValue resolves a friendly permission name to the API value.
func rolePermissionAPIValue(value string) (string, bool) {
	if apiValue, ok := rolePermissionLabelToAPI[value]; ok {
		return apiValue, true
	}
	if value == "Exception" {
		return value, true
	}
	if _, ok := rolePermissionAPIToLabel[value]; ok {
		return value, true
	}
	return "", false
}

// rolePermissionLabel resolves an API permission value to a friendly name.
func rolePermissionLabel(value string) string {
	if label, ok := rolePermissionAPIToLabel[value]; ok {
		return label
	}
	return value
}

// rolePermissionListToAPI validates and converts permissions to API values.
func rolePermissionListToAPI(values []string, diags *diag.Diagnostics, fieldName string) []string {
	if len(values) == 0 {
		return nil
	}

	apiValues := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		apiValue, ok := rolePermissionAPIValue(value)
		if !ok {
			diags.AddError(
				"Invalid role permission",
				fmt.Sprintf("%s contains unsupported value %q.", fieldName, value),
			)
			continue
		}
		if _, exists := seen[apiValue]; exists {
			continue
		}
		seen[apiValue] = struct{}{}
		apiValues = append(apiValues, apiValue)
	}

	slices.Sort(apiValues)
	return apiValues
}

// rolePermissionListToLabels converts API permission values to friendly names.
func rolePermissionListToLabels(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	labels := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "Exception" {
			continue
		}
		label := rolePermissionLabel(value)
		if _, exists := seen[label]; exists {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}

	slices.Sort(labels)
	return labels
}

// rolePermissionHasAll reports whether the permission list includes all access.
func rolePermissionHasAll(values []string) bool {
	return slices.Contains(values, "all")
}
