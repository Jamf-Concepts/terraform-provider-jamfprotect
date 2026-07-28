// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ action.Action = (*DeleteComputerAction)(nil)
var _ action.ActionWithConfigure = (*DeleteComputerAction)(nil)

// DeleteComputerAction removes computer records from the Jamf Protect tenant.
type DeleteComputerAction struct {
	computerAction
}

// DeleteComputerActionModel is the action configuration.
type DeleteComputerActionModel struct {
	ComputerUUIDs types.Set `tfsdk:"computer_uuids"`
}

// NewDeleteComputerAction constructs the action.
func NewDeleteComputerAction() action.Action {
	return &DeleteComputerAction{}
}

// Metadata sets the action type name.
func (a *DeleteComputerAction) Metadata(ctx context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_delete_computer"
}

// Schema defines the action configuration.
func (a *DeleteComputerAction) Schema(ctx context.Context, req action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = actionschema.Schema{
		MarkdownDescription: "Removes one or more computer records from the Jamf Protect tenant (`deleteComputer`). " +
			"Target computers with `computer_uuids`, sourced from the `jamfprotect_computers` data source. " +
			"Deleting a computer that no longer exists is a no-op with a warning, so an offboarding pipeline is safe to re-run.\n\n" +
			"~> **This is destructive and irreversible.** The computer's Jamf Protect record — including its alert history and insights data — is removed and cannot be restored. " +
			"It does **not** uninstall the Jamf Protect agent: unless the endpoint has also been unenrolled on the Jamf Pro side (or the Protect configuration profile removed), the Mac re-enrols and reappears in the tenant at its next check-in.\n\n" +
			"Terraform 1.14 supports no destroy-time action events, so clearing a plan's computers so `jamfprotect_plan` can be destroyed is a direct invocation: `terraform apply -invoke=action.jamfprotect_delete_computer.<name>` before `terraform destroy`.",
		Attributes: computerTargetAttributes("delete"),
	}
}

// Configure binds the provider-supplied Jamf Protect client to the action.
func (a *DeleteComputerAction) Configure(ctx context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	a.configure(ctx, req, resp)
}

// Invoke deletes each targeted computer record. Every target is looked up first
// so progress and warning messages can name the host, and so an already-deleted
// computer is reported as a skip rather than a failure.
func (a *DeleteComputerAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	if !a.ensureClient(resp) {
		return
	}

	var data DeleteComputerActionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	uuids := resolveTargets(ctx, data.ComputerUUIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(uuids) == 0 {
		resp.Diagnostics.AddWarning(
			"No Computers Targeted",
			"computer_uuids resolved to an empty set, so no computer records were deleted. This is expected when the selecting expression matches no computers.",
		)
		return
	}

	var failures []string
	deleted := 0
	for i, uuid := range uuids {
		computer, err := a.client.GetComputer(ctx, uuid)
		if computerMissing(err) || (err == nil && computer == nil) {
			resp.Diagnostics.AddWarning(
				"Computer Already Deleted",
				fmt.Sprintf("Computer %s does not exist in Jamf Protect, so there was nothing to delete.", uuid),
			)
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", uuid, err))
			continue
		}

		label := computerLabel(uuid, computer)
		resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Deleting computer %s (%d/%d)", label, i+1, len(uuids))})

		if err := a.client.DeleteComputer(ctx, uuid); err != nil {
			if common.IsNotFoundError(err) {
				resp.Diagnostics.AddWarning(
					"Computer Already Deleted",
					fmt.Sprintf("Computer %s was deleted by something else before this action reached it.", label),
				)
				continue
			}
			failures = append(failures, fmt.Sprintf("%s: %s", label, err))
			continue
		}
		deleted++
	}

	if len(failures) > 0 {
		resp.Diagnostics.AddError(
			"Delete Computer Failed",
			fmt.Sprintf("Unable to delete %d of %d computer record(s):\n%s", len(failures), len(uuids), failureSummary(failures)),
		)
		return
	}

	resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Deleted %d computer record(s)", deleted)})
}
