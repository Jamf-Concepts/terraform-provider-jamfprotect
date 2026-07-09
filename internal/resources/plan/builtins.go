// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

// systemPlanNames contains the names of plans that are Jamf-provided built-ins
// (present in every tenant). They can be excluded from list results via the
// list resource's exclude_builtins option.
var systemPlanNames = map[string]struct{}{
	"Default": {},
}

// isSystemPlanName returns true when the plan is a Jamf-provided built-in.
func isSystemPlanName(name string) bool {
	_, ok := systemPlanNames[name]
	return ok
}
