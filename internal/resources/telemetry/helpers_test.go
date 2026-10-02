// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"slices"
	"testing"
)

// TestEventsFromFlags_Individual verifies each category flag produces its expected events.
func TestEventsFromFlags_Individual(t *testing.T) {
	tests := []struct {
		name     string
		flags    telemetryEventFlags
		expected []string
	}{
		{
			name:     "apps and processes",
			flags:    telemetryEventFlags{LogAppsProcesses: true},
			expected: logApplicationsAndProcessesEvents,
		},
		{
			name:     "access and authentication",
			flags:    telemetryEventFlags{LogAccessAuth: true},
			expected: logAccessAndAuthenticationEvents,
		},
		{
			name:     "users and groups",
			flags:    telemetryEventFlags{LogUsersGroups: true},
			expected: logUsersAndGroupsEvents,
		},
		{
			name:     "persistence",
			flags:    telemetryEventFlags{LogPersistence: true},
			expected: logPersistenceEvents,
		},
		{
			name:     "hardware and software",
			flags:    telemetryEventFlags{LogHardwareSoftware: true},
			expected: logHardwareAndSoftwareEvents,
		},
		{
			name:     "apple security",
			flags:    telemetryEventFlags{LogAppleSecurity: true},
			expected: logAppleSecurityEvents,
		},
		{
			name:     "system",
			flags:    telemetryEventFlags{LogSystem: true},
			expected: logSystemEvents,
		},
		{
			name:     "network",
			flags:    telemetryEventFlags{LogNetwork: true},
			expected: logNetworkEvents,
		},
		{
			name:     "no flags",
			flags:    telemetryEventFlags{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventsFromFlags(tt.flags, nil)
			if !slices.Equal(got, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

// TestEventsFromFlags_AllEnabled verifies all flags enabled produces the full deduplicated event list.
func TestEventsFromFlags_AllEnabled(t *testing.T) {
	flags := telemetryEventFlags{
		LogAppsProcesses:    true,
		LogAccessAuth:       true,
		LogUsersGroups:      true,
		LogPersistence:      true,
		LogHardwareSoftware: true,
		LogAppleSecurity:    true,
		LogSystem:           true,
		LogNetwork:          true,
	}

	got := eventsFromFlags(flags, nil)

	// Count total unique events across all categories.
	allEvents := make(map[string]bool)
	for _, list := range [][]string{
		logApplicationsAndProcessesEvents,
		logAccessAndAuthenticationEvents,
		logUsersAndGroupsEvents,
		logPersistenceEvents,
		logHardwareAndSoftwareEvents,
		logAppleSecurityEvents,
		logSystemEvents,
		logNetworkEvents,
	} {
		for _, e := range list {
			allEvents[e] = true
		}
	}

	if len(got) != len(allEvents) {
		t.Fatalf("expected %d unique events, got %d", len(allEvents), len(got))
	}

	// Verify no duplicates.
	seen := make(map[string]bool)
	for _, event := range got {
		if seen[event] {
			t.Errorf("duplicate event: %q", event)
		}
		seen[event] = true
	}
}

// TestFlagsFromEvents_Individual verifies each category's events map back to the correct flag.
func TestFlagsFromEvents_Individual(t *testing.T) {
	tests := []struct {
		name     string
		events   []string
		expected telemetryEventFlags
	}{
		{
			name:     "apps and processes",
			events:   logApplicationsAndProcessesEvents,
			expected: telemetryEventFlags{LogAppsProcesses: true},
		},
		{
			name:     "access and authentication",
			events:   logAccessAndAuthenticationEvents,
			expected: telemetryEventFlags{LogAccessAuth: true},
		},
		{
			name:     "users and groups",
			events:   logUsersAndGroupsEvents,
			expected: telemetryEventFlags{LogUsersGroups: true},
		},
		{
			name:     "persistence",
			events:   logPersistenceEvents,
			expected: telemetryEventFlags{LogPersistence: true},
		},
		{
			name:     "hardware and software",
			events:   logHardwareAndSoftwareEvents,
			expected: telemetryEventFlags{LogHardwareSoftware: true},
		},
		{
			name:     "apple security",
			events:   logAppleSecurityEvents,
			expected: telemetryEventFlags{LogAppleSecurity: true},
		},
		{
			name:     "system",
			events:   logSystemEvents,
			expected: telemetryEventFlags{LogSystem: true},
		},
		{
			name:     "network",
			events:   logNetworkEvents,
			expected: telemetryEventFlags{LogNetwork: true},
		},
		{
			name:     "empty events",
			events:   []string{},
			expected: telemetryEventFlags{},
		},
		{
			name:     "nil events",
			events:   nil,
			expected: telemetryEventFlags{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flagsFromEvents(tt.events)
			if got != tt.expected {
				t.Errorf("expected %+v, got %+v", tt.expected, got)
			}
		})
	}
}

// TestFlagsFromEvents_PartialCategory verifies that a category with any event missing reads as disabled.
func TestFlagsFromEvents_PartialCategory(t *testing.T) {
	tests := []struct {
		name   string
		events []string
	}{
		{name: "single event", events: []string{"sudo"}},
		{name: "all but one", events: logAccessAndAuthenticationEvents[1:]},
		{name: "single event plus unmodelled", events: []string{"login_login", "xpc_connect"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flagsFromEvents(tt.events)
			if got != (telemetryEventFlags{}) {
				t.Errorf("expected no flags for a partial category, got %+v", got)
			}
		})
	}
}

// TestEventsFromFlags_RoundTrip verifies that flags → events → flags produces the same flags.
func TestEventsFromFlags_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		flags telemetryEventFlags
	}{
		{
			name: "all enabled",
			flags: telemetryEventFlags{
				LogAppsProcesses:    true,
				LogAccessAuth:       true,
				LogUsersGroups:      true,
				LogPersistence:      true,
				LogHardwareSoftware: true,
				LogAppleSecurity:    true,
				LogSystem:           true,
				LogNetwork:          true,
			},
		},
		{
			name: "mixed flags",
			flags: telemetryEventFlags{
				LogAppsProcesses: true,
				LogUsersGroups:   true,
				LogSystem:        true,
			},
		},
		{
			name:  "none enabled",
			flags: telemetryEventFlags{},
		},
		{
			name:  "single flag",
			flags: telemetryEventFlags{LogPersistence: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := eventsFromFlags(tt.flags, nil)
			roundTripped := flagsFromEvents(events)
			if roundTripped != tt.flags {
				t.Errorf("round-trip mismatch:\n  original:     %+v\n  events:       %v\n  round-tripped: %+v", tt.flags, events, roundTripped)
			}
		})
	}
}

// TestAppendEvents_Deduplication verifies that duplicate events are not added.
func TestAppendEvents_Deduplication(t *testing.T) {
	seen := map[string]bool{}
	base := appendEvents(nil, []string{"exec", "chroot"}, seen)
	base = appendEvents(base, []string{"exec", "sudo"}, seen)

	expected := []string{"exec", "chroot", "sudo"}
	if !slices.Equal(base, expected) {
		t.Errorf("expected %v, got %v", expected, base)
	}
}

// TestUnknownEventsIgnored verifies that unmodelled events do not affect category flags.
func TestUnknownEventsIgnored(t *testing.T) {
	events := append([]string{"unknown_future_event"}, logApplicationsAndProcessesEvents...)
	got := flagsFromEvents(events)
	if got != (telemetryEventFlags{LogAppsProcesses: true}) {
		t.Errorf("expected only LogAppsProcesses, got %+v", got)
	}
}

// TestEventsFromFlags_AdditionalEvents verifies additional events follow the category events without duplicates.
func TestEventsFromFlags_AdditionalEvents(t *testing.T) {
	got := eventsFromFlags(telemetryEventFlags{LogPersistence: true}, []string{"xpc_connect", "fork", "xpc_connect"})
	expected := append(slices.Clone(logPersistenceEvents), "xpc_connect", "fork")
	if !slices.Equal(got, expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

// TestEventsFromFlags_RoundTripWithAdditionalEvents verifies flags and additional events survive an API round trip.
func TestEventsFromFlags_RoundTripWithAdditionalEvents(t *testing.T) {
	flags := telemetryEventFlags{LogAccessAuth: true, LogSystem: true}
	additional := []string{"xpc_connect", "setuid"}

	events := eventsFromFlags(flags, additional)
	if got := flagsFromEvents(events); got != flags {
		t.Errorf("flags round-trip mismatch: expected %+v, got %+v", flags, got)
	}
	if got := unmodelledEvents(events); !slices.Equal(got, additional) {
		t.Errorf("additional events round-trip mismatch: expected %v, got %v", additional, got)
	}
}

// TestUnmodelledEvents verifies only events outside every category are returned, once each, in order.
func TestUnmodelledEvents(t *testing.T) {
	tests := []struct {
		name     string
		events   []string
		expected []string
	}{
		{name: "nil", events: nil, expected: []string{}},
		{name: "only category events", events: []string{"sudo", "exec", "network_connect"}, expected: []string{}},
		{name: "mixed", events: []string{"login_login", "xpc_connect", "exec", "fork"}, expected: []string{"xpc_connect", "fork"}},
		{name: "duplicates", events: []string{"fork", "fork", "setuid"}, expected: []string{"fork", "setuid"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unmodelledEvents(tt.events)
			if !slices.Equal(got, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

// TestEventCategoryAttribute verifies events map to the attribute of the category that collects them.
func TestEventCategoryAttribute(t *testing.T) {
	for _, category := range telemetryEventCategories {
		for _, event := range category.Events {
			got, ok := eventCategoryAttribute(event)
			if !ok || got != category.Attribute {
				t.Errorf("event %q: expected %q, got %q (found=%v)", event, category.Attribute, got, ok)
			}
		}
	}
	if got, ok := eventCategoryAttribute("xpc_connect"); ok {
		t.Errorf("expected xpc_connect to have no category, got %q", got)
	}
}
