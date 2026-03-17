// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computer

import (
	"context"
	"testing"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildComputerModel_AllFields tests buildComputerModel with all fields populated.
func TestBuildComputerModel_AllFields(t *testing.T) {
	uuid := "test-uuid-123"
	serial := "C02ABC123"
	hostName := "test-mac.local"
	modelName := "MacBookPro18,1"
	osMajor := int64(14)
	osMinor := int64(1)
	osPatch := int64(0)
	arch := "arm64"
	certID := "cert-123"
	memSize := int64(17179869184) // 16 GB
	osString := "macOS 14.1"
	kernelVer := "23.1.0"
	installType := "pkg"
	label := "Test Label"
	created := "2024-01-01T00:00:00Z"
	updated := "2024-01-02T00:00:00Z"
	version := "5.0.0"
	checkin := "2024-01-03T00:00:00Z"
	configHash := "abc123"
	tags := []string{"production", "finance"}
	sigVer := int64(21286)
	planID := "plan-123"
	planName := "Default Plan"
	planHash := "plan-hash"
	insightsFail := int64(2)
	insightsUpdated := "2024-01-04T00:00:00Z"
	connStatus := "CONNECTED"
	lastConn := "2024-01-05T00:00:00Z"
	lastConnIP := "192.168.1.100"
	lastDisconn := "2024-01-06T00:00:00Z"
	lastDisconnReason := "sleep"
	webProtActive := true
	fdaStatus := "Authorized"
	pendingPlanCount := int64(2)

	computer := jamfprotect.Computer{
		UUID:              &uuid,
		Serial:            &serial,
		HostName:          &hostName,
		ModelName:         &modelName,
		OSMajor:           &osMajor,
		OSMinor:           &osMinor,
		OSPatch:           &osPatch,
		Arch:              &arch,
		CertID:            &certID,
		MemorySize:        &memSize,
		OSString:          &osString,
		KernelVersion:     &kernelVer,
		InstallType:       &installType,
		Label:             &label,
		Created:           &created,
		Updated:           &updated,
		Version:           &version,
		Checkin:           &checkin,
		ConfigHash:        &configHash,
		Tags:              &tags,
		SignaturesVersion: &sigVer,
		Plan: &jamfprotect.ComputerPlan{
			ID:   &planID,
			Name: &planName,
			Hash: &planHash,
		},
		InsightsStatsFail:       &insightsFail,
		InsightsUpdated:         &insightsUpdated,
		ConnectionStatus:        &connStatus,
		LastConnection:          &lastConn,
		LastConnectionIP:        &lastConnIP,
		LastDisconnection:       &lastDisconn,
		LastDisconnectionReason: &lastDisconnReason,
		WebProtectionActive:     &webProtActive,
		FullDiskAccess:          &fdaStatus,
		PendingPlan:             &pendingPlanCount,
	}

	model := buildComputerModel(computer)

	// Verify all fields are set correctly
	if model.UUID.ValueString() != uuid {
		t.Errorf("UUID = %v, want %v", model.UUID.ValueString(), uuid)
	}
	if model.Serial.ValueString() != serial {
		t.Errorf("Serial = %v, want %v", model.Serial.ValueString(), serial)
	}
	if model.HostName.ValueString() != hostName {
		t.Errorf("HostName = %v, want %v", model.HostName.ValueString(), hostName)
	}
	if model.ModelName.ValueString() != modelName {
		t.Errorf("ModelName = %v, want %v", model.ModelName.ValueString(), modelName)
	}
	if model.OSMajor.ValueInt64() != osMajor {
		t.Errorf("OSMajor = %v, want %v", model.OSMajor.ValueInt64(), osMajor)
	}
	if model.WebProtectionActive.ValueBool() != webProtActive {
		t.Errorf("WebProtectionActive = %v, want %v", model.WebProtectionActive.ValueBool(), webProtActive)
	}
	if model.FullDiskAccess.ValueString() != fdaStatus {
		t.Errorf("FullDiskAccess = %v, want %v", model.FullDiskAccess.ValueString(), fdaStatus)
	}
	if model.PendingPlan.ValueInt64() != pendingPlanCount {
		t.Errorf("PendingPlan = %v, want %v", model.PendingPlan.ValueInt64(), pendingPlanCount)
	}

	// Verify tags
	if model.Tags.IsNull() {
		t.Error("Tags should not be null")
	}
	var modelTags []string
	model.Tags.ElementsAs(context.Background(), &modelTags, false)
	if len(modelTags) != 2 {
		t.Errorf("Tags length = %v, want 2", len(modelTags))
	}

	// Verify plan
	if model.Plan.IsNull() {
		t.Error("Plan should not be null")
	}
}

// TestBuildComputerModel_NullFields tests buildComputerModel with null/empty fields.
func TestBuildComputerModel_NullFields(t *testing.T) {
	uuid := "test-uuid-123"

	computer := jamfprotect.Computer{
		UUID: &uuid,
		// All other fields nil
	}

	model := buildComputerModel(computer)

	// Verify UUID is set
	if model.UUID.ValueString() != uuid {
		t.Errorf("UUID = %v, want %v", model.UUID.ValueString(), uuid)
	}

	// Verify other fields are null
	if !model.Serial.IsNull() {
		t.Error("Serial should be null")
	}
	if !model.HostName.IsNull() {
		t.Error("HostName should be null")
	}
	if !model.Tags.IsNull() {
		t.Error("Tags should be null when not provided")
	}
	if !model.Plan.IsNull() {
		t.Error("Plan should be null when not provided")
	}
}

// TestBuildComputerModel_EmptyTags tests buildComputerModel with empty tags slice.
func TestBuildComputerModel_EmptyTags(t *testing.T) {
	uuid := "test-uuid-123"
	emptyTags := []string{}

	computer := jamfprotect.Computer{
		UUID: &uuid,
		Tags: &emptyTags,
	}

	model := buildComputerModel(computer)

	// Empty tags should result in null set
	if !model.Tags.IsNull() {
		t.Error("Tags should be null for empty slice")
	}
}

// TestComputerDataSourceAttributes validates the schema attributes.
func TestComputerDataSourceAttributes(t *testing.T) {
	attrs := computerDataSourceAttributes()

	// Check that key attributes exist
	requiredAttrs := []string{
		"uuid", "serial", "host_name", "model_name",
		"os_major", "os_minor", "os_patch", "arch",
		"tags", "plan", "connection_status",
		"web_protection_active", "full_disk_access",
	}

	for _, attr := range requiredAttrs {
		if _, ok := attrs[attr]; !ok {
			t.Errorf("Missing required attribute: %s", attr)
		}
	}

	// Verify uuid is computed by default
	uuidAttr := attrs["uuid"]
	if uuidAttr == nil {
		t.Fatal("uuid attribute is nil")
	}
}

// TestComputerPlanAttrTypes validates the plan attribute types.
func TestComputerPlanAttrTypes(t *testing.T) {
	if len(computerPlanAttrTypes) != 3 {
		t.Errorf("computerPlanAttrTypes length = %v, want 3", len(computerPlanAttrTypes))
	}

	if computerPlanAttrTypes["id"] != types.StringType {
		t.Error("Plan id should be StringType")
	}
	if computerPlanAttrTypes["name"] != types.StringType {
		t.Error("Plan name should be StringType")
	}
	if computerPlanAttrTypes["hash"] != types.StringType {
		t.Error("Plan hash should be StringType")
	}
}
