// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

// telemetryEventFlags groups telemetry event category flags.
type telemetryEventFlags struct {
	LogAppsProcesses    bool
	LogAccessAuth       bool
	LogUsersGroups      bool
	LogPersistence      bool
	LogHardwareSoftware bool
	LogAppleSecurity    bool
	LogSystem           bool
}

// eventsFromFlags builds the event list from the selected categories.
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

// appendEvents adds unique events from a category to the list.
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

// flagsFromEvents derives category flags from the event list.
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

// hasAnyEvent reports whether any event from the list exists in the set.
func hasAnyEvent(set map[string]bool, events []string) bool {
	for _, event := range events {
		if set[event] {
			return true
		}
	}
	return false
}
