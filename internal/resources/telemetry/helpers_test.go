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
			name:     "no flags",
			flags:    telemetryEventFlags{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventsFromFlags(tt.flags)
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
	}

	got := eventsFromFlags(flags)

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

// TestFlagsFromEvents_SingleEvent verifies that a single event from a category activates the flag.
func TestFlagsFromEvents_SingleEvent(t *testing.T) {
	// A single "exec" event should activate LogAppsProcesses.
	flags := flagsFromEvents([]string{"exec"})
	if !flags.LogAppsProcesses {
		t.Error("expected LogAppsProcesses to be true for event 'exec'")
	}
	if flags.LogAccessAuth {
		t.Error("expected LogAccessAuth to be false")
	}

	// A single "sudo" event should activate LogAccessAuth.
	flags = flagsFromEvents([]string{"sudo"})
	if !flags.LogAccessAuth {
		t.Error("expected LogAccessAuth to be true for event 'sudo'")
	}
	if flags.LogAppsProcesses {
		t.Error("expected LogAppsProcesses to be false")
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
			events := eventsFromFlags(tt.flags)
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

// TestUnknownEventsIgnored verifies that unknown events from the API don't crash flagsFromEvents.
func TestUnknownEventsIgnored(t *testing.T) {
	flags := flagsFromEvents([]string{"unknown_future_event", "exec"})
	if !flags.LogAppsProcesses {
		t.Error("expected LogAppsProcesses to be true for event 'exec'")
	}
	// Unknown event should not cause any other flags to be set.
	if flags.LogAccessAuth || flags.LogUsersGroups || flags.LogPersistence ||
		flags.LogHardwareSoftware || flags.LogAppleSecurity || flags.LogSystem {
		t.Error("unexpected flag set from unknown event")
	}
}
