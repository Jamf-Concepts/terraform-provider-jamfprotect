// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

// Package computeractions implements the Jamf Protect computer actions:
// jamfprotect_set_computer_plan (move computers to a different plan) and
// jamfprotect_delete_computer (remove computer records from the tenant).
//
// SDK methods used:
//   jamfprotect.Client.SetComputerPlan  (mutation setComputerPlan)
//   jamfprotect.Client.DeleteComputer   (mutation deleteComputer)
//   jamfprotect.Client.GetComputer      (query getComputer — existence checks and check-in polling)
//
// Computer enrolment is owned by the Jamf Protect agent, not by Terraform, so
// these operations are actions rather than managed resources. Both actions take
// a set of computer_uuids, sourced from the jamfprotect_computers data source; a
// single-element set targets one computer.
//
// Terraform 1.14 has no destroy-time action events (before_destroy /
// after_destroy error at validation), so the offboarding workflow — clear a
// plan's computers so jamfprotect_plan can be destroyed — uses direct
// invocation: `terraform apply -invoke=action.<type>.<name>`. Wiring an action
// to a resource lifecycle.action_trigger (before_create / after_create /
// before_update / after_update) is the secondary pattern, suited to plan
// migrations.
//
// An empty computer_uuids set is a deliberate no-op: a for-expression over
// jamfprotect_computers that matches nothing means the fleet is already in the
// desired state, so re-running an offboarding pipeline stays safe.

package computeractions

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
)

// computerAction shares Configure and client handling across the computer actions.
type computerAction struct {
	client *jamfprotect.Client
}

// configure binds the provider-supplied Jamf Protect client to the action.
func (a *computerAction) configure(_ context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	a.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ensureClient guarantees Configure completed successfully before Invoke.
func (a *computerAction) ensureClient(resp *action.InvokeResponse) bool {
	if a.client != nil {
		return true
	}

	resp.Diagnostics.AddError(
		"Provider Not Configured",
		"The Jamf Protect client was not configured. Re-run terraform init/apply so the provider can configure successfully.",
	)
	return false
}

// computerTargetAttributes returns the computer_uuids selector shared by both
// computer actions, so the targeting contract and its documentation stay
// identical across them. verb names the operation in the attribute description,
// for example "move" or "delete".
func computerTargetAttributes(verb string) map[string]actionschema.Attribute {
	return map[string]actionschema.Attribute{
		"computer_uuids": actionschema.SetAttribute{
			Required:    true,
			ElementType: types.StringType,
			MarkdownDescription: fmt.Sprintf(
				"UUIDs of the computers to %s, as reported by the `uuid` attribute of the `jamfprotect_computer` / `jamfprotect_computers` data sources. Pass a single-element set to target one computer. An empty set is a no-op, so a `for` expression over `jamfprotect_computers` that matches nothing is safe to re-run.",
				verb,
			),
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(validators.UUID()),
			},
		},
	}
}

// resolveTargets flattens the configured selector into a sorted, deduplicated
// list of UUIDs. Sorting keeps progress output and error messages deterministic;
// computer_uuids is a set, so it carries no meaningful order.
func resolveTargets(ctx context.Context, bulk types.Set, diags *diag.Diagnostics) []string {
	uuids := common.SetToStrings(ctx, bulk, diags)

	slices.Sort(uuids)
	return slices.Compact(uuids)
}

// computerMissing reports whether an error means the computer UUID no longer
// exists in the tenant. Jamf Protect never returns ErrNotFound for these calls,
// so common.IsNotFoundError alone does not detect a deleted computer — every
// missing-computer response is a GraphQL error. Live-confirmed 2026-07-28:
//
//	getComputer     — nil computer plus "Cannot return null for non-nullable
//	                  type: 'ID' within parent 'Computer' (/getComputer/uuid)"
//	deleteComputer  — the same non-nullable error under /deleteComputer/uuid
//	setComputerPlan — "Computer with uuid '<uuid>' does not exist."
//
// The first two are the resolver returning null for a record that has gone,
// which the non-null schema then rejects; only setComputerPlan says so plainly.
// ErrNotFound is still checked first, in case the API grows a proper 404.
func computerMissing(err error) bool {
	if err == nil {
		return false
	}
	if common.IsNotFoundError(err) {
		return true
	}

	message := err.Error()
	if strings.Contains(message, "does not exist") {
		return true
	}

	return strings.Contains(message, "Cannot return null for non-nullable type") &&
		strings.Contains(message, "parent 'Computer'")
}

// failureSummary renders per-computer failures as an indented list for a single
// aggregated error diagnostic, so a bulk invocation reports every failure rather
// than stopping at the first.
func failureSummary(failures []string) string {
	return "  - " + strings.Join(failures, "\n  - ")
}

// computerLabel renders a computer for progress and diagnostic messages,
// preferring host name and serial when the record has been fetched.
func computerLabel(uuid string, c *jamfprotect.Computer) string {
	if c == nil {
		return uuid
	}

	var parts []string
	if c.HostName != nil && *c.HostName != "" {
		parts = append(parts, *c.HostName)
	}
	if c.Serial != nil && *c.Serial != "" {
		parts = append(parts, *c.Serial)
	}
	if len(parts) == 0 {
		return uuid
	}

	return fmt.Sprintf("%s (%s)", uuid, strings.Join(parts, ", "))
}
