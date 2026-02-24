// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"maps"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

// RBAC variable constants shared across service methods.
var (
	// rbacUser contains the RBAC flags used by user queries.
	rbacUser = map[string]any{
		"RBAC_Connection": true,
		"RBAC_Role":       true,
		"RBAC_Group":      true,
	}

	// rbacGroup contains the RBAC flags used by group queries.
	rbacGroup = map[string]any{
		"RBAC_Connection": true,
		"RBAC_Role":       true,
	}

	// rbacComputer contains the RBAC flags used by computer queries.
	rbacComputer = map[string]any{
		"RBAC_ThreatPreventionVersion": true,
		"RBAC_Plan":                    true,
		"RBAC_Insight":                 true,
	}

	// rbacPlan contains the RBAC flags used by plan/telemetry/analytic-set queries.
	rbacPlan = map[string]any{
		"RBAC_Plan": true,
	}

	// rbacAnalytic contains the RBAC flags used by exception-set queries.
	rbacAnalytic = map[string]any{
		"RBAC_Analytic": true,
	}
)

// mergeVars returns a new map combining base variables with additional maps.
func mergeVars(base map[string]any, extras ...map[string]any) map[string]any {
	result := make(map[string]any, len(base))
	maps.Copy(result, base)
	for _, extra := range extras {
		maps.Copy(result, extra)
	}
	return result
}

// Service provides Jamf Protect operations built on top of the transport client.
type Service struct {
	client *client.Client
}

// NewService creates a new Jamf Protect service wrapper.
func NewService(c *client.Client) *Service {
	return &Service{client: c}
}

// BaseURL returns the base URL configured for the underlying client.
func (s *Service) BaseURL() string {
	return s.client.BaseURL()
}
