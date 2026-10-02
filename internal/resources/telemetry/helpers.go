// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import "slices"

// telemetryEventFlags groups telemetry event category flags.
type telemetryEventFlags struct {
	LogAppsProcesses    bool
	LogAccessAuth       bool
	LogUsersGroups      bool
	LogPersistence      bool
	LogHardwareSoftware bool
	LogAppleSecurity    bool
	LogSystem           bool
	LogNetwork          bool
}

// eventsFromFlags builds the event list from the selected categories followed by the additional events.
func eventsFromFlags(flags telemetryEventFlags, additional []string) []string {
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
	if flags.LogNetwork {
		result = appendEvents(result, logNetworkEvents, seen)
	}
	return appendEvents(result, additional, seen)
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

// flagsFromEvents derives category flags from the event list. A flag is true only when every event in its category is present.
func flagsFromEvents(events []string) telemetryEventFlags {
	set := map[string]bool{}
	for _, event := range events {
		set[event] = true
	}

	return telemetryEventFlags{
		LogAppsProcesses:    hasAllEvents(set, logApplicationsAndProcessesEvents),
		LogAccessAuth:       hasAllEvents(set, logAccessAndAuthenticationEvents),
		LogUsersGroups:      hasAllEvents(set, logUsersAndGroupsEvents),
		LogPersistence:      hasAllEvents(set, logPersistenceEvents),
		LogHardwareSoftware: hasAllEvents(set, logHardwareAndSoftwareEvents),
		LogAppleSecurity:    hasAllEvents(set, logAppleSecurityEvents),
		LogSystem:           hasAllEvents(set, logSystemEvents),
		LogNetwork:          hasAllEvents(set, logNetworkEvents),
	}
}

// hasAllEvents reports whether every event from the list exists in the set.
func hasAllEvents(set map[string]bool, events []string) bool {
	for _, event := range events {
		if !set[event] {
			return false
		}
	}
	return true
}

// eventCategoryAttribute returns the category attribute that collects the event, if any.
func eventCategoryAttribute(event string) (string, bool) {
	for _, category := range telemetryEventCategories {
		if slices.Contains(category.Events, event) {
			return category.Attribute, true
		}
	}
	return "", false
}

// unmodelledEvents returns the unique events that no category collects, in their original order.
func unmodelledEvents(events []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0)
	for _, event := range events {
		if seen[event] {
			continue
		}
		seen[event] = true
		if _, ok := eventCategoryAttribute(event); ok {
			continue
		}
		result = append(result, event)
	}
	return result
}
