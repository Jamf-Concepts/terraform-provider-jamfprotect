// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "github.com/smithjw/terraform-provider-jamfprotect/internal/client"

// Service provides Jamf Protect operations built on top of the transport client.
type Service struct {
	client *client.Client
}

// NewService creates a new Jamf Protect service wrapper.
func NewService(c *client.Client) *Service {
	return &Service{client: c}
}
