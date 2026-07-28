// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// defaultCheckinTimeout is the wait_for_checkin deadline when timeout is unset.
// Agents check in every few minutes, so a fleet-wide plan change normally
// settles well inside this window.
const defaultCheckinTimeout = 15 * time.Minute

// checkinPollInterval is the delay between wait_for_checkin polling rounds.
const checkinPollInterval = 30 * time.Second

var _ action.Action = (*SetComputerPlanAction)(nil)
var _ action.ActionWithConfigure = (*SetComputerPlanAction)(nil)

// SetComputerPlanAction moves computers to a different Jamf Protect plan.
type SetComputerPlanAction struct {
	computerAction
}

// SetComputerPlanActionModel is the action configuration.
type SetComputerPlanActionModel struct {
	ComputerUUIDs  types.Set    `tfsdk:"computer_uuids"`
	PlanID         types.String `tfsdk:"plan_id"`
	WaitForCheckin types.Bool   `tfsdk:"wait_for_checkin"`
	Timeout        types.String `tfsdk:"timeout"`
}

// NewSetComputerPlanAction constructs the action.
func NewSetComputerPlanAction() action.Action {
	return &SetComputerPlanAction{}
}

// Metadata sets the action type name.
func (a *SetComputerPlanAction) Metadata(ctx context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_set_computer_plan"
}

// Schema defines the action configuration.
func (a *SetComputerPlanAction) Schema(ctx context.Context, req action.SchemaRequest, resp *action.SchemaResponse) {
	attributes := computerTargetAttributes("move")
	attributes["plan_id"] = actionschema.StringAttribute{
		Required:            true,
		MarkdownDescription: "ID of the plan to move the computers to, as reported by `jamfprotect_plan.<name>.id` or the `jamfprotect_plans` data source.",
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
	}
	attributes["wait_for_checkin"] = actionschema.BoolAttribute{
		Optional: true,
		MarkdownDescription: "Wait for each computer to settle on the new plan before the action completes. The assignment is recorded immediately as the computer's `pending_plan`, but `plan.id` only changes when the Jamf Protect agent next checks in. " +
			"Set this to `true` when a later operation depends on the move having landed — notably destroying the old `jamfprotect_plan`. A pending move does **not** release the old plan: while `plan.id` still references it, `deletePlan` fails with " +
			"`Action blocked due to dependencies on this resource`, and only succeeds once the agent has applied the change. Defaults to `false`.",
	}
	attributes["timeout"] = actionschema.StringAttribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf(
			"How long to wait when `wait_for_checkin = true`, as a Go duration string (for example `\"30m\"`). Defaults to `%q`. Ignored when `wait_for_checkin` is unset or `false`.",
			defaultCheckinTimeout.String(),
		),
		Validators: []validator.String{
			Duration(),
		},
	}

	resp.Schema = actionschema.Schema{
		MarkdownDescription: "Moves one or more computers to a different Jamf Protect plan (`setComputerPlan`). " +
			"Target computers with `computer_uuids`, sourced from the `jamfprotect_computers` data source. " +
			"The plan assignment is recorded immediately and applied on the endpoint at the agent's next check-in; set `wait_for_checkin = true` to block until it has landed. " +
			"Terraform 1.14 supports no destroy-time action events, so invoke this directly with `terraform apply -invoke=action.jamfprotect_set_computer_plan.<name>`, or wire it to a resource's `lifecycle.action_trigger` for create/update events.",
		Attributes: attributes,
	}
}

// Configure binds the provider-supplied Jamf Protect client to the action.
func (a *SetComputerPlanAction) Configure(ctx context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	a.configure(ctx, req, resp)
}

// Invoke assigns the plan to each targeted computer, then waits for the fleet to
// check in on it when wait_for_checkin is set. A failure on any computer is
// reported once every target has been attempted.
func (a *SetComputerPlanAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	if !a.ensureClient(resp) {
		return
	}

	var data SetComputerPlanActionModel
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
			"computer_uuids resolved to an empty set, so no plan assignment was made. This is expected when the selecting expression matches no computers.",
		)
		return
	}

	planID := data.PlanID.ValueString()
	timeout, ok := a.resolveTimeout(data.Timeout, resp)
	if !ok {
		return
	}

	var failures []string
	var moved []string
	for i, uuid := range uuids {
		resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Assigning plan %s to computer %s (%d/%d)", planID, uuid, i+1, len(uuids))})

		computer, err := a.client.SetComputerPlan(ctx, uuid, planID)
		switch {
		case computerMissing(err):
			resp.Diagnostics.AddWarning(
				"Computer Not Found",
				fmt.Sprintf("Computer %s no longer exists in Jamf Protect, so no plan was assigned.", uuid),
			)
		case err != nil:
			failures = append(failures, fmt.Sprintf("%s: %s", uuid, err))
		case computer == nil:
			resp.Diagnostics.AddWarning(
				"Computer Not Found",
				fmt.Sprintf("Jamf Protect returned no computer for %s, so no plan was assigned. The computer record has most likely been deleted.", uuid),
			)
		default:
			moved = append(moved, uuid)
		}
	}

	if len(failures) > 0 {
		resp.Diagnostics.AddError(
			"Set Computer Plan Failed",
			fmt.Sprintf("Unable to assign plan %s to %d of %d computer(s):\n%s", planID, len(failures), len(uuids), failureSummary(failures)),
		)
		return
	}

	resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Plan %s assigned to %d computer(s)", planID, len(moved))})

	if data.WaitForCheckin.ValueBool() && len(moved) > 0 {
		a.waitForCheckin(ctx, resp, moved, planID, timeout)
	}
}

// resolveTimeout parses the configured timeout, falling back to
// defaultCheckinTimeout. The value is validated at plan time by Duration(); this
// re-parse is the apply-time guard.
func (a *SetComputerPlanAction) resolveTimeout(configured types.String, resp *action.InvokeResponse) (time.Duration, bool) {
	if !common.IsKnownString(configured) {
		return defaultCheckinTimeout, true
	}

	timeout, err := time.ParseDuration(configured.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Timeout",
			fmt.Sprintf("Unable to parse timeout %q as a duration: %s", configured.ValueString(), err),
		)
		return 0, false
	}

	return timeout, true
}

// waitForCheckin polls the targeted computers until each has settled on the
// requested plan, or the timeout expires. Every computer is polled in each round
// so one slow endpoint does not serialise the whole fleet's wait.
func (a *SetComputerPlanAction) waitForCheckin(ctx context.Context, resp *action.InvokeResponse, uuids []string, planID string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	pending := slices.Clone(uuids)
	lastSeen := make(map[string]string, len(uuids))

	resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Waiting up to %s for %d computer(s) to check in on plan %s", timeout, len(pending), planID)})

	for {
		var stillPending []string
		for _, uuid := range pending {
			computer, err := a.client.GetComputer(ctx, uuid)
			if computerMissing(err) || (err == nil && computer == nil) {
				resp.Diagnostics.AddWarning(
					"Computer Not Found",
					fmt.Sprintf("Computer %s disappeared while waiting for check-in, so it is no longer being waited on.", uuid),
				)
				continue
			}
			if err != nil {
				resp.Diagnostics.AddError(
					"Set Computer Plan Wait Failed",
					fmt.Sprintf("Unable to read computer %s while waiting for check-in: %s. The plan assignment was made; only the wait failed.", uuid, err),
				)
				return
			}

			lastSeen[uuid] = checkinStateSummary(uuid, computer)
			if planSettled(computer, planID) {
				resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("Computer %s checked in on plan %s", computerLabel(uuid, computer), planID)})
				continue
			}
			stillPending = append(stillPending, uuid)
		}

		pending = stillPending
		if len(pending) == 0 {
			resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("All computers have checked in on plan %s", planID)})
			return
		}

		if !time.Now().Add(checkinPollInterval).Before(deadline) {
			resp.Diagnostics.AddError(
				"Timed Out Waiting For Check-In",
				fmt.Sprintf(
					"%d of %d computer(s) had not settled on plan %s after %s. The plan assignment was made and will still apply when each agent next checks in; only the wait timed out. Last observed state:\n%s",
					len(pending), len(uuids), planID, timeout, failureSummary(pendingSummaries(pending, lastSeen)),
				),
			)
			return
		}

		resp.SendProgress(action.InvokeProgressEvent{Message: fmt.Sprintf("%d computer(s) still pending on plan %s; polling again in %s", len(pending), planID, checkinPollInterval)})

		select {
		case <-ctx.Done():
			resp.Diagnostics.AddError(
				"Set Computer Plan Wait Cancelled",
				fmt.Sprintf("Cancelled while waiting for %d computer(s) to check in on plan %s: %s. The plan assignment was made.", len(pending), planID, ctx.Err()),
			)
			return
		case <-time.After(checkinPollInterval):
		}
	}
}

// planSettled reports whether a computer has settled on the requested plan: the
// record points at that plan and no plan change is still outstanding. pendingPlan
// is an Int in the Jamf Protect API; both null and 0 mean nothing is pending.
func planSettled(computer *jamfprotect.Computer, planID string) bool {
	if computer.Plan == nil || computer.Plan.ID == nil || *computer.Plan.ID != planID {
		return false
	}

	return computer.PendingPlan == nil || *computer.PendingPlan == 0
}

// checkinStateSummary renders the plan-settlement signals for a computer, so a
// wait timeout reports what the tenant actually returned rather than a bare UUID.
func checkinStateSummary(uuid string, computer *jamfprotect.Computer) string {
	planID := "none"
	if computer.Plan != nil && computer.Plan.ID != nil {
		planID = *computer.Plan.ID
	}
	pendingPlan := "null"
	if computer.PendingPlan != nil {
		pendingPlan = fmt.Sprintf("%d", *computer.PendingPlan)
	}
	checkin := "never"
	if computer.Checkin != nil && *computer.Checkin != "" {
		checkin = *computer.Checkin
	}

	return fmt.Sprintf("%s: plan=%s pending_plan=%s checkin=%s", computerLabel(uuid, computer), planID, pendingPlan, checkin)
}

// pendingSummaries returns the last observed state of every still-pending
// computer, in a deterministic order.
func pendingSummaries(pending []string, lastSeen map[string]string) []string {
	summaries := make([]string, 0, len(pending))
	for _, uuid := range slices.Sorted(maps.Keys(lastSeen)) {
		if slices.Contains(pending, uuid) {
			summaries = append(summaries, lastSeen[uuid])
		}
	}

	return summaries
}
