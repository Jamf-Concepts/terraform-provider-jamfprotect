// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TelemetryV2ResourceModel maps the resource schema data.
type TelemetryV2ResourceModel struct {
	ID                 types.String   `tfsdk:"id"`
	Name               types.String   `tfsdk:"name"`
	Description        types.String   `tfsdk:"description"`
	LogFiles           types.List     `tfsdk:"log_files"`
	LogFileCollection  types.Bool     `tfsdk:"log_file_collection"`
	PerformanceMetrics types.Bool     `tfsdk:"performance_metrics"`
	Events             types.List     `tfsdk:"events"`
	FileHashing        types.Bool     `tfsdk:"file_hashing"`
	Created            types.String   `tfsdk:"created"`
	Updated            types.String   `tfsdk:"updated"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// API model (matches the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type telemetryV2APIModel struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LogFiles           []string `json:"logFiles"`
	LogFileCollection  bool     `json:"logFileCollection"`
	PerformanceMetrics bool     `json:"performanceMetrics"`
	Events             []string `json:"events"`
	FileHashing        bool     `json:"fileHashing"`
	Created            string   `json:"created"`
	Updated            string   `json:"updated"`
}
