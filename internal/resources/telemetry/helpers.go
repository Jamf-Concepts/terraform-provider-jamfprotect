// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var (
	logApplicationsAndProcessesEvents = []string{"chroot", "cs_invalidated", "exec"}
	logAccessAndAuthenticationEvents  = []string{"authentication", "login_login", "login_logout", "lw_session_lock", "lw_session_login", "lw_session_logout", "lw_session_unlock", "openssh_login", "openssh_logout", "pty_close", "pty_grant", "screensharing_attach", "screensharing_detach", "su", "sudo"}
	logUsersAndGroupsEvents           = []string{"od_attribute_set", "od_attribute_value_add", "od_attribute_value_remove", "od_create_group", "od_create_user", "od_delete_group", "od_delete_user", "od_disable_user", "od_enable_user", "od_group_add", "od_group_remove", "od_group_set", "od_modify_password"}
	logPersistenceEvents              = []string{"btm_launch_item_add", "btm_launch_item_remove"}
	logHardwareAndSoftwareEvents      = []string{"mount", "remount", "unmount"}
	logAppleSecurityEvents            = []string{"gatekeeper_user_override", "xp_malware_detected", "xp_malware_remediated"}
	logSystemEvents                   = []string{"kextload", "kextunload", "profile_add", "profile_remove", "settime", "tcc_modify"}
)

type telemetryEventFlags struct {
	LogAppsProcesses    bool
	LogAccessAuth       bool
	LogUsersGroups      bool
	LogPersistence      bool
	LogHardwareSoftware bool
	LogAppleSecurity    bool
	LogSystem           bool
}

func eventsFromFlags(flags telemetryEventFlags) []string {
	seen := map[string]bool{}
	result := make([]string, 0)
	if flags.LogAppsProcesses {
		result = appendEvents(result, logApplicationsAndProcessesEvents, seen)
	}
	if flags.LogAccessAuth {
		result = appendEvents(result, logAccessAndAuthenticationEvents, seen)
	}
	if flags.LogUsersGroups {
		result = appendEvents(result, logUsersAndGroupsEvents, seen)
	}
	if flags.LogPersistence {
		result = appendEvents(result, logPersistenceEvents, seen)
	}
	if flags.LogHardwareSoftware {
		result = appendEvents(result, logHardwareAndSoftwareEvents, seen)
	}
	if flags.LogAppleSecurity {
		result = appendEvents(result, logAppleSecurityEvents, seen)
	}
	if flags.LogSystem {
		result = appendEvents(result, logSystemEvents, seen)
	}
	return result
}

func appendEvents(base []string, events []string, seen map[string]bool) []string {
	for _, event := range events {
		if seen[event] {
			continue
		}
		seen[event] = true
		base = append(base, event)
	}
	return base
}

func flagsFromEvents(events []string) telemetryEventFlags {
	set := map[string]bool{}
	for _, event := range events {
		set[event] = true
	}

	return telemetryEventFlags{
		LogAppsProcesses:    hasAnyEvent(set, logApplicationsAndProcessesEvents),
		LogAccessAuth:       hasAnyEvent(set, logAccessAndAuthenticationEvents),
		LogUsersGroups:      hasAnyEvent(set, logUsersAndGroupsEvents),
		LogPersistence:      hasAnyEvent(set, logPersistenceEvents),
		LogHardwareSoftware: hasAnyEvent(set, logHardwareAndSoftwareEvents),
		LogAppleSecurity:    hasAnyEvent(set, logAppleSecurityEvents),
		LogSystem:           hasAnyEvent(set, logSystemEvents),
	}
}

func hasAnyEvent(set map[string]bool, events []string) bool {
	for _, event := range events {
		if set[event] {
			return true
		}
	}
	return false
}

func (r *TelemetryV2Resource) buildInput(ctx context.Context, data TelemetryV2ResourceModel, diags *diag.Diagnostics) *jamfprotect.TelemetryV2Input {
	flags := telemetryEventFlags{
		LogAppsProcesses:    data.LogAppsProcesses.ValueBool(),
		LogAccessAuth:       data.LogAccessAuth.ValueBool(),
		LogUsersGroups:      data.LogUsersGroups.ValueBool(),
		LogPersistence:      data.LogPersistence.ValueBool(),
		LogHardwareSoftware: data.LogHardwareSoftware.ValueBool(),
		LogAppleSecurity:    data.LogAppleSecurity.ValueBool(),
		LogSystem:           data.LogSystem.ValueBool(),
	}

	input := &jamfprotect.TelemetryV2Input{
		Name:               data.Name.ValueString(),
		LogFileCollection:  data.DiagnosticReports.ValueBool(),
		PerformanceMetrics: data.PerformanceMetrics.ValueBool(),
		FileHashing:        data.FileHashes.ValueBool(),
		LogFiles:           common.ListToStrings(ctx, data.LogFilePath, diags),
		Events:             eventsFromFlags(flags),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	return input
}

func (r *TelemetryV2Resource) apiToState(_ context.Context, data *TelemetryV2ResourceModel, api jamfprotect.TelemetryV2, _ *diag.Diagnostics) {
	flags := flagsFromEvents(api.Events)

	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.DiagnosticReports = types.BoolValue(api.LogFileCollection)
	data.PerformanceMetrics = types.BoolValue(api.PerformanceMetrics)
	data.FileHashes = types.BoolValue(api.FileHashing)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.LogFilePath = common.StringsToList(api.LogFiles)
	data.LogAppsProcesses = types.BoolValue(flags.LogAppsProcesses)
	data.LogAccessAuth = types.BoolValue(flags.LogAccessAuth)
	data.LogUsersGroups = types.BoolValue(flags.LogUsersGroups)
	data.LogPersistence = types.BoolValue(flags.LogPersistence)
	data.LogHardwareSoftware = types.BoolValue(flags.LogHardwareSoftware)
	data.LogAppleSecurity = types.BoolValue(flags.LogAppleSecurity)
	data.LogSystem = types.BoolValue(flags.LogSystem)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
