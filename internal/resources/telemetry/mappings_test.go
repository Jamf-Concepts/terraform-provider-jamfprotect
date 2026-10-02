// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// esEventsAllowlist is a copy of the endpoint security event allowlist the Jamf Protect API
// validates telemetry events against, after replacing underscores with hyphens. Refresh it
// when Jamf adds events.
var esEventsAllowlist = []string{
	"exec", "open", "fork", "close", "create", "exchangedata",
	"exit", "get-task", "kextload", "kextunload", "link", "mmap",
	"mprotect", "mount", "unmount", "iokit-open", "rename", "setattrlist",
	"setextattr", "setflags", "setmode", "setowner", "signal", "unlink",
	"write", "file-provider-materialize", "file-provider-update", "readlink", "truncate", "lookup",
	"chdir", "getattrlist", "stat", "access", "chroot", "utimes",
	"clone", "fcntl", "getextattr", "listextattr", "readdir", "deleteextattr",
	"fsgetpath", "dup", "settime", "uipc-bind", "uipc-connect", "setacl",
	"pty-grant", "pty-close", "proc-check", "searchfs", "proc-suspend-resume", "cs-invalidated",
	"get-task-name", "trace", "remote-thread-create", "remount", "get-task-read", "get-task-inspect",
	"setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid",
	"copyfile", "openssh-login", "openssh-logout", "xp-malware-detected", "xp-malware-remediated", "lw-session-lock",
	"lw-session-unlock", "lw-session-login", "lw-session-logout", "login-login", "login-logout", "authentication",
	"btm-launch-item-add", "btm-launch-item-remove", "screensharing-attach", "screensharing-detach", "authorization-judgement", "authorization-petition",
	"xpc-connect", "sudo", "su", "od-attribute-set", "od-attribute-value-add", "od-attribute-value-remove",
	"od-create-group", "od-create-user", "od-delete-group", "od-delete-user", "od-disable-user", "od-enable-user",
	"od-group-add", "od-group-remove", "od-group-set", "od-modify-password", "profile-add", "profile-remove",
	"gatekeeper-user-override", "tcc-modify", "network-connect", "bios-uefi", "file-collection", "system-performance",
	"log-collection",
}

// TestTelemetryEventCategories_InAPIAllowlist verifies every category event is an event the API accepts.
func TestTelemetryEventCategories_InAPIAllowlist(t *testing.T) {
	allowed := make(map[string]bool, len(esEventsAllowlist))
	for _, event := range esEventsAllowlist {
		allowed[event] = true
	}

	for _, category := range telemetryEventCategories {
		for _, event := range category.Events {
			if !allowed[strings.ReplaceAll(event, "_", "-")] {
				t.Errorf("%s event %q is not in the API allowlist", category.Attribute, event)
			}
		}
	}
}

// TestTelemetryEventCategories_Disjoint verifies no event belongs to more than one category.
func TestTelemetryEventCategories_Disjoint(t *testing.T) {
	owner := map[string]string{}
	for _, category := range telemetryEventCategories {
		for _, event := range category.Events {
			if existing, ok := owner[event]; ok {
				t.Errorf("event %q is in both %s and %s", event, existing, category.Attribute)
			}
			owner[event] = category.Attribute
		}
	}
}

// TestTelemetryEventCategories_MatchSchema verifies every category names a boolean attribute of the resource schema.
func TestTelemetryEventCategories_MatchSchema(t *testing.T) {
	resp := &resource.SchemaResponse{}
	NewTelemetryV2Resource().Schema(context.Background(), resource.SchemaRequest{}, resp)

	for _, category := range telemetryEventCategories {
		if _, ok := resp.Schema.Attributes[category.Attribute]; !ok {
			t.Errorf("category attribute %q is not in the resource schema", category.Attribute)
		}
	}
}
