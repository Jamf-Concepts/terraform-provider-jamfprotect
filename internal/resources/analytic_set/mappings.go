// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

// systemAnalyticSetNames contains the names of analytic sets that are managed by the system and should be excluded from listings.
var systemAnalyticSetNames = map[string]struct{}{
	"Advanced Threat Controls": {},
	"Tamper Prevention":        {},
}

// isSystemAnalyticSetName returns true when the analytic set should be excluded from listings.
func isSystemAnalyticSetName(name string) bool {
	_, ok := systemAnalyticSetNames[name]
	return ok
}
