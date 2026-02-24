// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UserResourceModel maps the resource schema data.
type UserResourceModel struct {
	ID                     types.String   `tfsdk:"id"`
	Email                  types.String   `tfsdk:"email"`
	IdentityProviderID     types.String   `tfsdk:"identity_provider_id"`
	RoleIDs                types.Set      `tfsdk:"role_ids"`
	GroupIDs               types.Set      `tfsdk:"group_ids"`
	SendEmailNotifications types.Bool     `tfsdk:"send_email_notifications"`
	EmailSeverity          types.String   `tfsdk:"email_severity"`
	Created                types.String   `tfsdk:"created"`
	Updated                types.String   `tfsdk:"updated"`
	Timeouts               timeouts.Value `tfsdk:"timeouts"`
}
