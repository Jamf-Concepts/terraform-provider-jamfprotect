// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// ConfigureClient extracts the *jamfprotect.Client from provider data.
// Returns nil without error when providerData is nil (provider not yet configured).
func ConfigureClient(providerData any, diags *diag.Diagnostics) *jamfprotect.Client {
	if providerData == nil {
		return nil
	}

	c, ok := providerData.(*jamfprotect.Client)
	if !ok {
		diags.AddError(
			"Unexpected Configure Type",
			fmt.Sprintf("Expected *jamfprotect.Client, got: %T", providerData),
		)
		return nil
	}

	return c
}
