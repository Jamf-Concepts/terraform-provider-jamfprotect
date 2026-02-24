// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func TestMapRuleTypeUIToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "AppSigningInfo", input: "App Signing Info", expected: "AppSigningInfo"},
		{name: "TeamId", input: "Team ID", expected: "TeamId"},
		{name: "Executable", input: "Process Path", expected: "Executable"},
		{name: "PlatformBinary", input: "Platform Binary", expected: "PlatformBinary"},
		{name: "User", input: "User", expected: "User"},
		{name: "Path", input: "File Path", expected: "Path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapRuleTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.expected {
				t.Errorf("mapRuleTypeUIToAPI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapRuleTypeUIToAPI_EmptyString(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapRuleTypeUIToAPI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected error for empty string: %s", diags.Errors()[0].Detail())
	}
	if result != "" {
		t.Errorf("mapRuleTypeUIToAPI(\"\") = %q, want \"\"", result)
	}
}

func TestMapRuleTypeUIToAPI_AlreadyAPIValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "AppSigningInfo", input: "AppSigningInfo"},
		{name: "TeamId", input: "TeamId"},
		{name: "Executable", input: "Executable"},
		{name: "PlatformBinary", input: "PlatformBinary"},
		{name: "Path", input: "Path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapRuleTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.input {
				t.Errorf("mapRuleTypeUIToAPI(%q) = %q, want %q (pass-through)", tt.input, result, tt.input)
			}
		})
	}
}

func TestMapRuleTypeUIToAPI_Invalid(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapRuleTypeUIToAPI("NonExistent", &diags)
	if !diags.HasError() {
		t.Fatal("expected error for invalid rule type, got none")
	}
	if result != "" {
		t.Errorf("mapRuleTypeUIToAPI(\"NonExistent\") = %q, want \"\"", result)
	}
}

func TestMapRuleTypeAPIToUI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "AppSigningInfo", input: "AppSigningInfo", expected: "App Signing Info"},
		{name: "TeamId", input: "TeamId", expected: "Team ID"},
		{name: "Executable", input: "Executable", expected: "Process Path"},
		{name: "PlatformBinary", input: "PlatformBinary", expected: "Platform Binary"},
		{name: "User", input: "User", expected: "User"},
		{name: "Path", input: "Path", expected: "File Path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapRuleTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.expected {
				t.Errorf("mapRuleTypeAPIToUI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapRuleTypeAPIToUI_EmptyString(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapRuleTypeAPIToUI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected error for empty string: %s", diags.Errors()[0].Detail())
	}
	if result != "" {
		t.Errorf("mapRuleTypeAPIToUI(\"\") = %q, want \"\"", result)
	}
}

func TestMapRuleTypeAPIToUI_AlreadyUIValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "AppSigningInfo", input: "App Signing Info"},
		{name: "TeamID", input: "Team ID"},
		{name: "ProcessPath", input: "Process Path"},
		{name: "PlatformBinary", input: "Platform Binary"},
		{name: "FilePath", input: "File Path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapRuleTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.input {
				t.Errorf("mapRuleTypeAPIToUI(%q) = %q, want %q (pass-through)", tt.input, result, tt.input)
			}
		})
	}
}

func TestMapRuleTypeAPIToUI_Invalid(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapRuleTypeAPIToUI("NonExistent", &diags)
	if !diags.HasError() {
		t.Fatal("expected error for invalid rule type, got none")
	}
	if result != "NonExistent" {
		t.Errorf("mapRuleTypeAPIToUI(\"NonExistent\") = %q, want \"NonExistent\"", result)
	}
}

func TestMapEsRuleTypeUIToAPI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "AppSigningInfo", input: "App Signing Info", expected: "AppSigningInfo"},
		{name: "TeamId", input: "Team ID", expected: "TeamId"},
		{name: "Executable", input: "Process Path", expected: "Executable"},
		{name: "PlatformBinary", input: "Platform Binary", expected: "PlatformBinary"},
		{name: "User", input: "User", expected: "User"},
		{name: "Groups", input: "Group", expected: "Groups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapEsRuleTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.expected {
				t.Errorf("mapEsRuleTypeUIToAPI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapEsRuleTypeUIToAPI_EmptyString(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapEsRuleTypeUIToAPI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected error for empty string: %s", diags.Errors()[0].Detail())
	}
	if result != "" {
		t.Errorf("mapEsRuleTypeUIToAPI(\"\") = %q, want \"\"", result)
	}
}

func TestMapEsRuleTypeUIToAPI_AlreadyAPIValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "AppSigningInfo", input: "AppSigningInfo"},
		{name: "TeamId", input: "TeamId"},
		{name: "Executable", input: "Executable"},
		{name: "PlatformBinary", input: "PlatformBinary"},
		{name: "Groups", input: "Groups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapEsRuleTypeUIToAPI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.input {
				t.Errorf("mapEsRuleTypeUIToAPI(%q) = %q, want %q (pass-through)", tt.input, result, tt.input)
			}
		})
	}
}

func TestMapEsRuleTypeUIToAPI_Invalid(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapEsRuleTypeUIToAPI("NonExistent", &diags)
	if !diags.HasError() {
		t.Fatal("expected error for invalid ES rule type, got none")
	}
	if result != "" {
		t.Errorf("mapEsRuleTypeUIToAPI(\"NonExistent\") = %q, want \"\"", result)
	}
}

func TestMapEsRuleTypeAPIToUI_ValidMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "AppSigningInfo", input: "AppSigningInfo", expected: "App Signing Info"},
		{name: "TeamId", input: "TeamId", expected: "Team ID"},
		{name: "Executable", input: "Executable", expected: "Process Path"},
		{name: "PlatformBinary", input: "PlatformBinary", expected: "Platform Binary"},
		{name: "User", input: "User", expected: "User"},
		{name: "Groups", input: "Groups", expected: "Group"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapEsRuleTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.expected {
				t.Errorf("mapEsRuleTypeAPIToUI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapEsRuleTypeAPIToUI_EmptyString(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapEsRuleTypeAPIToUI("", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected error for empty string: %s", diags.Errors()[0].Detail())
	}
	if result != "" {
		t.Errorf("mapEsRuleTypeAPIToUI(\"\") = %q, want \"\"", result)
	}
}

func TestMapEsRuleTypeAPIToUI_AlreadyUIValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "AppSigningInfo", input: "App Signing Info"},
		{name: "TeamID", input: "Team ID"},
		{name: "ProcessPath", input: "Process Path"},
		{name: "PlatformBinary", input: "Platform Binary"},
		{name: "Group", input: "Group"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			result := mapEsRuleTypeAPIToUI(tt.input, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected error: %s", diags.Errors()[0].Detail())
			}
			if result != tt.input {
				t.Errorf("mapEsRuleTypeAPIToUI(%q) = %q, want %q (pass-through)", tt.input, result, tt.input)
			}
		})
	}
}

func TestMapEsRuleTypeAPIToUI_Invalid(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	result := mapEsRuleTypeAPIToUI("NonExistent", &diags)
	if !diags.HasError() {
		t.Fatal("expected error for invalid ES rule type, got none")
	}
	if result != "NonExistent" {
		t.Errorf("mapEsRuleTypeAPIToUI(\"NonExistent\") = %q, want \"NonExistent\"", result)
	}
}

func TestIsEsExceptionType_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expected: true},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expected: true},
		{name: "FileSystemEvent", input: "File System Event", expected: false},
		{name: "DownloadEvent", input: "Download Event", expected: false},
		{name: "ProcessEvent", input: "Process Event", expected: false},
		{name: "ScreenshotEvent", input: "Screenshot Event", expected: false},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expected: false},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expected: false},
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expected: false},
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expected: false},
		{name: "EmptyString", input: "", expected: false},
		{name: "Invalid", input: "NonExistent", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isEsExceptionType(tt.input)
			if result != tt.expected {
				t.Errorf("isEsExceptionType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExceptionTypeRequiresSubType_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expected: true},
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expected: true},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expected: true},
		{name: "FileSystemEvent", input: "File System Event", expected: false},
		{name: "DownloadEvent", input: "Download Event", expected: false},
		{name: "ProcessEvent", input: "Process Event", expected: false},
		{name: "ScreenshotEvent", input: "Screenshot Event", expected: false},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expected: false},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expected: false},
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expected: false},
		{name: "EmptyString", input: "", expected: false},
		{name: "Invalid", input: "NonExistent", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := exceptionTypeRequiresSubType(tt.input)
			if result != tt.expected {
				t.Errorf("exceptionTypeRequiresSubType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExceptionTypeForbidsSubType_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expected: true},
		{name: "FileSystemEvent", input: "File System Event", expected: true},
		{name: "DownloadEvent", input: "Download Event", expected: true},
		{name: "ProcessEvent", input: "Process Event", expected: true},
		{name: "ScreenshotEvent", input: "Screenshot Event", expected: true},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expected: true},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expected: true},
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expected: false},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expected: false},
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expected: false},
		{name: "EmptyString", input: "", expected: false},
		{name: "Invalid", input: "NonExistent", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := exceptionTypeForbidsSubType(tt.input)
			if result != tt.expected {
				t.Errorf("exceptionTypeForbidsSubType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExceptionTypeActivity_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		input            string
		expectedActivity string
		expectedOK       bool
	}{
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expectedActivity: "Telemetry", expectedOK: true},
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expectedActivity: "Analytics", expectedOK: true},
		{name: "FileSystemEvent", input: "File System Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "DownloadEvent", input: "Download Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "ProcessEvent", input: "Process Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "ScreenshotEvent", input: "Screenshot Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expectedActivity: "Analytics", expectedOK: true},
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expectedActivity: "", expectedOK: false},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expectedActivity: "", expectedOK: false},
		{name: "EmptyString", input: "", expectedActivity: "", expectedOK: false},
		{name: "Invalid", input: "NonExistent", expectedActivity: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			activity, ok := exceptionTypeActivity(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("exceptionTypeActivity(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if activity != tt.expectedActivity {
				t.Errorf("exceptionTypeActivity(%q) = %q, want %q", tt.input, activity, tt.expectedActivity)
			}
		})
	}
}

func TestExceptionTypeAnalyticTypes_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		expectedTypes []string
		expectedOK    bool
	}{
		{name: "FileSystemEvent", input: "File System Event", expectedTypes: []string{"GPFSEvent"}, expectedOK: true},
		{name: "DownloadEvent", input: "Download Event", expectedTypes: []string{"GPDownloadEvent"}, expectedOK: true},
		{name: "ProcessEvent", input: "Process Event", expectedTypes: []string{"GPProcessEvent"}, expectedOK: true},
		{name: "ScreenshotEvent", input: "Screenshot Event", expectedTypes: []string{"GPScreenshotEvent"}, expectedOK: true},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expectedTypes: []string{"GPKeylogRegisterEvent"}, expectedOK: true},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expectedTypes: []string{"GPClickEvent"}, expectedOK: true},
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expectedTypes: nil, expectedOK: false},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expectedTypes: nil, expectedOK: false},
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expectedTypes: nil, expectedOK: false},
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expectedTypes: nil, expectedOK: false},
		{name: "EmptyString", input: "", expectedTypes: nil, expectedOK: false},
		{name: "Invalid", input: "NonExistent", expectedTypes: nil, expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			types, ok := exceptionTypeAnalyticTypes(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("exceptionTypeAnalyticTypes(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if len(types) != len(tt.expectedTypes) {
				t.Fatalf("exceptionTypeAnalyticTypes(%q) returned %d types, want %d", tt.input, len(types), len(tt.expectedTypes))
			}
			for i, v := range types {
				if v != tt.expectedTypes[i] {
					t.Errorf("exceptionTypeAnalyticTypes(%q)[%d] = %q, want %q", tt.input, i, v, tt.expectedTypes[i])
				}
			}
		})
	}
}

func TestMapEsExceptionSubType_OverrideEndpointThreatPrevention(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		subType                string
		expectedIgnoreActivity string
		expectedIgnoreListType string
		expectedIgnoreListSub  string
		expectedEventType      string
		expectedOK             bool
	}{
		{name: "Process", subType: "Process", expectedIgnoreActivity: "ThreatPrevention", expectedIgnoreListType: "ignore", expectedIgnoreListSub: "", expectedEventType: "", expectedOK: true},
		{name: "ParentProcess", subType: "Parent Process", expectedIgnoreActivity: "ThreatPrevention", expectedIgnoreListType: "ignore", expectedIgnoreListSub: "parent", expectedEventType: "", expectedOK: true},
		{name: "ResponsibleProcess", subType: "Responsible Process", expectedIgnoreActivity: "ThreatPrevention", expectedIgnoreListType: "ignore", expectedIgnoreListSub: "responsible", expectedEventType: "", expectedOK: true},
		{name: "Invalid", subType: "Invalid", expectedIgnoreActivity: "", expectedIgnoreListType: "", expectedIgnoreListSub: "", expectedEventType: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			activity, listType, listSub, eventType, ok := mapEsExceptionSubType("Override Endpoint Threat Prevention", tt.subType)
			if ok != tt.expectedOK {
				t.Fatalf("mapEsExceptionSubType(\"Override Endpoint Threat Prevention\", %q) ok = %v, want %v", tt.subType, ok, tt.expectedOK)
			}
			if activity != tt.expectedIgnoreActivity {
				t.Errorf("activity = %q, want %q", activity, tt.expectedIgnoreActivity)
			}
			if listType != tt.expectedIgnoreListType {
				t.Errorf("listType = %q, want %q", listType, tt.expectedIgnoreListType)
			}
			if listSub != tt.expectedIgnoreListSub {
				t.Errorf("listSub = %q, want %q", listSub, tt.expectedIgnoreListSub)
			}
			if eventType != tt.expectedEventType {
				t.Errorf("eventType = %q, want %q", eventType, tt.expectedEventType)
			}
		})
	}
}

func TestMapEsExceptionSubType_IgnoreForTelemetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		subType                string
		expectedIgnoreActivity string
		expectedIgnoreListType string
		expectedIgnoreListSub  string
		expectedEventType      string
		expectedOK             bool
	}{
		{name: "ExecProcess", subType: "Exec Process", expectedIgnoreActivity: "TelemetryV2", expectedIgnoreListType: "events", expectedIgnoreListSub: "", expectedEventType: "exec", expectedOK: true},
		{name: "SourceProcess", subType: "Source Process", expectedIgnoreActivity: "TelemetryV2", expectedIgnoreListType: "sourceIgnore", expectedIgnoreListSub: "", expectedEventType: "", expectedOK: true},
		{name: "SourceParentProcess", subType: "Source Parent Process", expectedIgnoreActivity: "TelemetryV2", expectedIgnoreListType: "sourceIgnore", expectedIgnoreListSub: "parent", expectedEventType: "", expectedOK: true},
		{name: "SourceResponsibleProcess", subType: "Source Responsible Process", expectedIgnoreActivity: "TelemetryV2", expectedIgnoreListType: "sourceIgnore", expectedIgnoreListSub: "responsible", expectedEventType: "", expectedOK: true},
		{name: "Invalid", subType: "Invalid", expectedIgnoreActivity: "", expectedIgnoreListType: "", expectedIgnoreListSub: "", expectedEventType: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			activity, listType, listSub, eventType, ok := mapEsExceptionSubType("Ignore for Telemetry", tt.subType)
			if ok != tt.expectedOK {
				t.Fatalf("mapEsExceptionSubType(\"Ignore for Telemetry\", %q) ok = %v, want %v", tt.subType, ok, tt.expectedOK)
			}
			if activity != tt.expectedIgnoreActivity {
				t.Errorf("activity = %q, want %q", activity, tt.expectedIgnoreActivity)
			}
			if listType != tt.expectedIgnoreListType {
				t.Errorf("listType = %q, want %q", listType, tt.expectedIgnoreListType)
			}
			if listSub != tt.expectedIgnoreListSub {
				t.Errorf("listSub = %q, want %q", listSub, tt.expectedIgnoreListSub)
			}
			if eventType != tt.expectedEventType {
				t.Errorf("eventType = %q, want %q", eventType, tt.expectedEventType)
			}
		})
	}
}

func TestMapEsExceptionSubType_UnsupportedExceptionType(t *testing.T) {
	t.Parallel()
	activity, listType, listSub, eventType, ok := mapEsExceptionSubType("File System Event", "Process")
	if ok {
		t.Fatal("expected ok=false for unsupported exception type, got true")
	}
	if activity != "" || listType != "" || listSub != "" || eventType != "" {
		t.Errorf("expected all empty strings for unsupported exception type, got (%q, %q, %q, %q)", activity, listType, listSub, eventType)
	}
}

func TestMapApiExceptionType_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		activity        string
		analyticTypes   []string
		analyticUUID    string
		expectedType    string
		expectedSubType string
		expectedOK      bool
	}{
		{name: "Telemetry", activity: "Telemetry", analyticTypes: nil, analyticUUID: "", expectedType: "Ignore for Telemetry (Deprecated)", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsWithUUID", activity: "Analytics", analyticTypes: nil, analyticUUID: "some-uuid", expectedType: "Ignore for Analytic", expectedSubType: "some-uuid", expectedOK: true},
		{name: "AnalyticsGPFSEvent", activity: "Analytics", analyticTypes: []string{"GPFSEvent"}, analyticUUID: "", expectedType: "File System Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsGPDownloadEvent", activity: "Analytics", analyticTypes: []string{"GPDownloadEvent"}, analyticUUID: "", expectedType: "Download Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsGPProcessEvent", activity: "Analytics", analyticTypes: []string{"GPProcessEvent"}, analyticUUID: "", expectedType: "Process Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsGPScreenshotEvent", activity: "Analytics", analyticTypes: []string{"GPScreenshotEvent"}, analyticUUID: "", expectedType: "Screenshot Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsGPKeylogRegisterEvent", activity: "Analytics", analyticTypes: []string{"GPKeylogRegisterEvent"}, analyticUUID: "", expectedType: "Keylog Register Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsGPClickEvent", activity: "Analytics", analyticTypes: []string{"GPClickEvent"}, analyticUUID: "", expectedType: "Synthetic Click Event", expectedSubType: "", expectedOK: true},
		{name: "AnalyticsMultipleTypes", activity: "Analytics", analyticTypes: []string{"GPFSEvent", "GPProcessEvent"}, analyticUUID: "", expectedType: "", expectedSubType: "", expectedOK: false},
		{name: "AnalyticsNoTypesNoUUID", activity: "Analytics", analyticTypes: nil, analyticUUID: "", expectedType: "", expectedSubType: "", expectedOK: false},
		{name: "AnalyticsUnknownType", activity: "Analytics", analyticTypes: []string{"Unknown"}, analyticUUID: "", expectedType: "", expectedSubType: "", expectedOK: false},
		{name: "UnknownActivity", activity: "Unknown", analyticTypes: nil, analyticUUID: "", expectedType: "", expectedSubType: "", expectedOK: false},
		{name: "EmptyActivity", activity: "", analyticTypes: nil, analyticUUID: "", expectedType: "", expectedSubType: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exType, subType, ok := mapApiExceptionType(tt.activity, tt.analyticTypes, tt.analyticUUID)
			if ok != tt.expectedOK {
				t.Fatalf("mapApiExceptionType(%q, %v, %q) ok = %v, want %v", tt.activity, tt.analyticTypes, tt.analyticUUID, ok, tt.expectedOK)
			}
			if exType != tt.expectedType {
				t.Errorf("exceptionType = %q, want %q", exType, tt.expectedType)
			}
			if subType != tt.expectedSubType {
				t.Errorf("subType = %q, want %q", subType, tt.expectedSubType)
			}
		})
	}
}

func TestMapApiEsExceptionType_ThreatPrevention(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		ignoreListSub   string
		expectedSubType string
		expectedOK      bool
	}{
		{name: "Process", ignoreListSub: "", expectedSubType: "Process", expectedOK: true},
		{name: "ParentProcess", ignoreListSub: "parent", expectedSubType: "Parent Process", expectedOK: true},
		{name: "ResponsibleProcess", ignoreListSub: "responsible", expectedSubType: "Responsible Process", expectedOK: true},
		{name: "Invalid", ignoreListSub: "invalid", expectedSubType: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exType, subType, ok := mapApiEsExceptionType("ThreatPrevention", "ignore", tt.ignoreListSub, "")
			if ok != tt.expectedOK {
				t.Fatalf("ok = %v, want %v", ok, tt.expectedOK)
			}
			if ok {
				if exType != "Override Endpoint Threat Prevention" {
					t.Errorf("exceptionType = %q, want \"Override Endpoint Threat Prevention\"", exType)
				}
				if subType != tt.expectedSubType {
					t.Errorf("subType = %q, want %q", subType, tt.expectedSubType)
				}
			}
		})
	}
}

func TestMapApiEsExceptionType_TelemetryV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		ignoreListType  string
		ignoreListSub   string
		eventType       string
		expectedSubType string
		expectedOK      bool
	}{
		{name: "ExecProcess", ignoreListType: "events", ignoreListSub: "", eventType: "exec", expectedSubType: "Exec Process", expectedOK: true},
		{name: "SourceProcess", ignoreListType: "sourceIgnore", ignoreListSub: "", eventType: "", expectedSubType: "Source Process", expectedOK: true},
		{name: "SourceParentProcess", ignoreListType: "sourceIgnore", ignoreListSub: "parent", eventType: "", expectedSubType: "Source Parent Process", expectedOK: true},
		{name: "SourceResponsibleProcess", ignoreListType: "sourceIgnore", ignoreListSub: "responsible", eventType: "", expectedSubType: "Source Responsible Process", expectedOK: true},
		{name: "SourceIgnoreInvalidSub", ignoreListType: "sourceIgnore", ignoreListSub: "invalid", eventType: "", expectedSubType: "", expectedOK: false},
		{name: "UnknownListType", ignoreListType: "unknown", ignoreListSub: "", eventType: "", expectedSubType: "", expectedOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exType, subType, ok := mapApiEsExceptionType("TelemetryV2", tt.ignoreListType, tt.ignoreListSub, tt.eventType)
			if ok != tt.expectedOK {
				t.Fatalf("ok = %v, want %v", ok, tt.expectedOK)
			}
			if ok {
				if exType != "Ignore for Telemetry" {
					t.Errorf("exceptionType = %q, want \"Ignore for Telemetry\"", exType)
				}
				if subType != tt.expectedSubType {
					t.Errorf("subType = %q, want %q", subType, tt.expectedSubType)
				}
			}
		})
	}
}

func TestMapApiEsExceptionType_UnknownActivity(t *testing.T) {
	t.Parallel()
	_, _, ok := mapApiEsExceptionType("Unknown", "ignore", "", "")
	if ok {
		t.Fatal("expected ok=false for unknown activity, got true")
	}
}

func TestMapApiEsExceptionType_ThreatPreventionWrongListType(t *testing.T) {
	t.Parallel()
	_, _, ok := mapApiEsExceptionType("ThreatPrevention", "wrong", "", "")
	if ok {
		t.Fatal("expected ok=false for wrong list type with ThreatPrevention, got true")
	}
}

func TestAnalyticTypeToExceptionTypeReverseLookup_All(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "FileSystemEvent", input: "File System Event", expected: true},
		{name: "DownloadEvent", input: "Download Event", expected: true},
		{name: "ProcessEvent", input: "Process Event", expected: true},
		{name: "ScreenshotEvent", input: "Screenshot Event", expected: true},
		{name: "KeylogRegisterEvent", input: "Keylog Register Event", expected: true},
		{name: "SyntheticClickEvent", input: "Synthetic Click Event", expected: true},
		{name: "OverrideEndpointThreatPrevention", input: "Override Endpoint Threat Prevention", expected: false},
		{name: "IgnoreForTelemetry", input: "Ignore for Telemetry", expected: false},
		{name: "IgnoreForTelemetryDeprecated", input: "Ignore for Telemetry (Deprecated)", expected: false},
		{name: "IgnoreForAnalytic", input: "Ignore for Analytic", expected: false},
		{name: "EmptyString", input: "", expected: false},
		{name: "Invalid", input: "NonExistent", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := analyticTypeToExceptionTypeReverseLookup(tt.input)
			if result != tt.expected {
				t.Errorf("analyticTypeToExceptionTypeReverseLookup(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
