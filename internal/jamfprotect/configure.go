// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

// ConfigureService extracts a *client.Client from provider data and returns
// a new Service. This is the shared implementation for all resource, data source,
// and list resource Configure methods.
func ConfigureService(providerData any, diags *diag.Diagnostics) *Service {
	if providerData == nil {
		return nil
	}
	c, ok := providerData.(*client.Client)
	if !ok {
		diags.AddError("Unexpected Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", providerData))
		return nil
	}
	return NewService(c)
}
