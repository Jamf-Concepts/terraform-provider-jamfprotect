// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestProviderSchema(t *testing.T) {
	t.Parallel()

	p := New("test")()
	resp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	// Verify required attributes exist.
	for _, attr := range []string{"url", "client_id", "client_secret"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("expected attribute %q in provider schema", attr)
		}
	}
}

func TestProviderMetadata(t *testing.T) {
	t.Parallel()

	p := New("1.2.3")()
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "jamfprotect" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect", resp.TypeName)
	}
	if resp.Version != "1.2.3" {
		t.Errorf("expected Version %q, got %q", "1.2.3", resp.Version)
	}
}

func TestAnalyticResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewAnalyticResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "input_type", "filter", "level", "severity", "tags", "categories", "snapshot_files", "analytic_actions", "context"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in analytic schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"uuid", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in analytic schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in analytic schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}
}

func TestPreventListResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewPreventListResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "type", "tags", "list"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in prevent list schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "entry_count", "created"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in prevent list schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in prevent list schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}
}

func TestUnifiedLoggingFilterResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewUnifiedLoggingFilterResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "filter", "level", "tags"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in unified logging filter schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"uuid", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in unified logging filter schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in unified logging filter schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// enabled should be optional + computed (has default).
	enabled, ok := resp.Schema.Attributes["enabled"]
	if !ok {
		t.Fatal("expected attribute 'enabled' in schema")
	}
	if !enabled.IsOptional() {
		t.Error("expected 'enabled' to be optional")
	}
	if !enabled.IsComputed() {
		t.Error("expected 'enabled' to be computed (has default)")
	}
}

func TestAnalyticResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewAnalyticResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_analytic" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_analytic", resp.TypeName)
	}
}

func TestPreventListResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewPreventListResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_prevent_list" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_prevent_list", resp.TypeName)
	}
}

func TestUnifiedLoggingFilterResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewUnifiedLoggingFilterResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_unified_logging_filter" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_unified_logging_filter", resp.TypeName)
	}
}

func TestActionConfigResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewActionConfigResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "alert_config"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in action config schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "hash", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in action config schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}
}

func TestActionConfigResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewActionConfigResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_action_config" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_action_config", resp.TypeName)
	}
}

func TestPlanResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewPlanResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "action_configs", "comms_config", "info_sync", "signatures_feed_config"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "hash", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	optionalAttrs := []string{"description", "log_level", "exception_sets", "telemetry", "telemetry_v2", "usb_control_set", "analytic_sets"}
	for _, attr := range optionalAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsOptional() {
			t.Errorf("expected attribute %q to be optional", attr)
		}
	}

	// log_level should be optional + computed (has default).
	logLevel, ok := resp.Schema.Attributes["log_level"]
	if !ok {
		t.Fatal("expected attribute 'log_level' in schema")
	}
	if !logLevel.IsOptional() {
		t.Error("expected 'log_level' to be optional")
	}
	if !logLevel.IsComputed() {
		t.Error("expected 'log_level' to be computed (has default)")
	}

	// auto_update should be optional + computed (has default).
	autoUpdate, ok := resp.Schema.Attributes["auto_update"]
	if !ok {
		t.Fatal("expected attribute 'auto_update' in schema")
	}
	if !autoUpdate.IsOptional() {
		t.Error("expected 'auto_update' to be optional")
	}
	if !autoUpdate.IsComputed() {
		t.Error("expected 'auto_update' to be computed (has default)")
	}
}

func TestPlanResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewPlanResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_plan" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_plan", resp.TypeName)
	}
}
