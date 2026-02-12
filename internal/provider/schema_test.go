// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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

	computedAttrs := []string{"id", "created", "updated"}
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

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in analytic schema")
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

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in prevent list schema")
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

	computedAttrs := []string{"id", "created", "updated"}
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

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in unified logging filter schema")
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

	// alert_config should be a SingleNestedAttribute containing data with 14 event types.
	alertConfigAttr, ok := resp.Schema.Attributes["alert_config"]
	if !ok {
		t.Fatal("expected attribute 'alert_config' in schema")
	}
	alertConfigNested, ok := alertConfigAttr.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("expected 'alert_config' to be a SingleNestedAttribute")
	}
	dataAttr, ok := alertConfigNested.Attributes["data"]
	if !ok {
		t.Fatal("expected 'data' attribute inside alert_config")
	}
	dataNested, ok := dataAttr.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("expected 'data' to be a SingleNestedAttribute")
	}

	eventTypes := []string{
		"binary", "click_event", "download_event", "file", "fs_event",
		"group", "proc_event", "process", "screenshot_event", "usb_event",
		"user", "gk_event", "keylog_register_event", "mrt_event",
	}
	for _, et := range eventTypes {
		etAttr, ok := dataNested.Attributes[et]
		if !ok {
			t.Errorf("expected event type %q in alert_config.data", et)
			continue
		}
		etNested, ok := etAttr.(schema.SingleNestedAttribute)
		if !ok {
			t.Errorf("expected event type %q to be a SingleNestedAttribute", et)
			continue
		}
		if _, ok := etNested.Attributes["attrs"]; !ok {
			t.Errorf("expected 'attrs' attribute in event type %q", et)
		}
		if _, ok := etNested.Attributes["related"]; !ok {
			t.Errorf("expected 'related' attribute in event type %q", et)
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in action config schema")
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

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in plan schema")
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

func TestUSBControlSetResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewUSBControlSetResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "default_mount_action", "rules"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in USB control set schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in USB control set schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in USB control set schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// default_message_action should be optional + computed.
	msgAction, ok := resp.Schema.Attributes["default_message_action"]
	if !ok {
		t.Fatal("expected attribute 'default_message_action' in USB control set schema")
	}
	if !msgAction.IsOptional() {
		t.Error("expected 'default_message_action' to be optional")
	}
	if !msgAction.IsComputed() {
		t.Error("expected 'default_message_action' to be computed")
	}

	// rules should be a ListNestedAttribute.
	rulesAttr, ok := resp.Schema.Attributes["rules"]
	if !ok {
		t.Fatal("expected attribute 'rules' in USB control set schema")
	}
	rulesNested, ok := rulesAttr.(schema.ListNestedAttribute)
	if !ok {
		t.Fatal("expected 'rules' to be a ListNestedAttribute")
	}

	// Verify rule nested attributes.
	ruleAttrs := rulesNested.NestedObject.Attributes
	for _, attr := range []string{"type", "mount_action"} {
		a, ok := ruleAttrs[attr]
		if !ok {
			t.Errorf("expected attribute %q in rules nested object", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected rule attribute %q to be required", attr)
		}
	}
	for _, attr := range []string{"message_action", "apply_to", "vendors", "serials", "products"} {
		if _, ok := ruleAttrs[attr]; !ok {
			t.Errorf("expected attribute %q in rules nested object", attr)
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in USB control set schema")
	}
}

func TestUSBControlSetResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewUSBControlSetResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_usb_control_set" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_usb_control_set", resp.TypeName)
	}
}

func TestTelemetryV2ResourceSchema(t *testing.T) {
	t.Parallel()

	r := NewTelemetryV2Resource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "log_files", "events"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in telemetry v2 schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// Boolean attrs should be optional + computed (have defaults).
	for _, attr := range []string{"log_file_collection", "performance_metrics", "file_hashing"} {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsOptional() {
			t.Errorf("expected attribute %q to be optional", attr)
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed (has default)", attr)
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in telemetry v2 schema")
	}
}

func TestTelemetryV2ResourceMetadata(t *testing.T) {
	t.Parallel()

	r := NewTelemetryV2Resource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_telemetry_v2" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_telemetry_v2", resp.TypeName)
	}
}
