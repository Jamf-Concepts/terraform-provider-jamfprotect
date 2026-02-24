// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"fmt"
)

// computerFields defines the GraphQL fragment for computer fields.
const computerFields = `
fragment ComputerFields on Computer {
    uuid
    serial
    hostName
    modelName
    osMajor
    osMinor
    osPatch
    arch @skip(if: $isList)
    certid @skip(if: $isList)
    memorySize @skip(if: $isList)
    osString
    kernelVersion @skip(if: $isList)
    installType @skip(if: $isList)
    label
    created
    updated
    version
    checkin
    configHash
    tags
    signaturesVersion @include(if: $RBAC_ThreatPreventionVersion)
    plan @include(if: $RBAC_Plan) {
        id
        name
        hash
    }
    insightsStatsFail @include(if: $RBAC_Insight)
    insightsUpdated @include(if: $RBAC_Insight)
    connectionStatus
    lastConnection
    lastConnectionIp
    lastDisconnection
    lastDisconnectionReason
    webProtectionActive
    fullDiskAccess
    pendingPlan
}
`

// listComputersQuery defines the GraphQL query for listing computers.
const listComputersQuery = `
query listComputers(
    $pageSize: Int,
    $nextToken: String,
    $direction: OrderDirection!,
    $field: [ComputerOrderField!],
    $filter: ComputerFiltersInput,
    $isList: Boolean!,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    listComputers(
        input: {
            next: $nextToken,
            order: {direction: $direction, field: $field},
            pageSize: $pageSize,
            filter: $filter
        }
    ) {
        items {
            ...ComputerFields
        }
        pageInfo {
            next
            total
        }
    }
}
` + computerFields

// getComputerQuery defines the GraphQL query for retrieving a computer by UUID.
const getComputerQuery = `
query getComputer(
    $uuid: ID!,
    $isList: Boolean!,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    getComputer(uuid: $uuid) {
        ...ComputerFields
    }
}
` + computerFields

// Computer represents a computer enrolled in Jamf Protect.
type Computer struct {
	UUID                    *string       `json:"uuid"`
	Serial                  *string       `json:"serial"`
	HostName                *string       `json:"hostName"`
	ModelName               *string       `json:"modelName"`
	OSMajor                 *int64        `json:"osMajor"`
	OSMinor                 *int64        `json:"osMinor"`
	OSPatch                 *int64        `json:"osPatch"`
	Arch                    *string       `json:"arch"`
	CertID                  *string       `json:"certid"`
	MemorySize              *int64        `json:"memorySize"`
	OSString                *string       `json:"osString"`
	KernelVersion           *string       `json:"kernelVersion"`
	InstallType             *string       `json:"installType"`
	Label                   *string       `json:"label"`
	Created                 *string       `json:"created"`
	Updated                 *string       `json:"updated"`
	Version                 *string       `json:"version"`
	Checkin                 *string       `json:"checkin"`
	ConfigHash              *string       `json:"configHash"`
	Tags                    *[]string     `json:"tags"`
	SignaturesVersion       *int64        `json:"signaturesVersion"`
	Plan                    *ComputerPlan `json:"plan"`
	InsightsStatsFail       *int64        `json:"insightsStatsFail"`
	InsightsUpdated         *string       `json:"insightsUpdated"`
	ConnectionStatus        *string       `json:"connectionStatus"`
	LastConnection          *string       `json:"lastConnection"`
	LastConnectionIP        *string       `json:"lastConnectionIp"`
	LastDisconnection       *string       `json:"lastDisconnection"`
	LastDisconnectionReason *string       `json:"lastDisconnectionReason"`
	WebProtectionActive     *bool         `json:"webProtectionActive"`
	FullDiskAccess          *string       `json:"fullDiskAccess"`
	PendingPlan             *int64        `json:"pendingPlan"`
}

// ComputerPlan represents a plan assigned to a computer.
type ComputerPlan struct {
	ID   *string `json:"id"`
	Name *string `json:"name"`
	Hash *string `json:"hash"`
}

// ListComputersResponse represents the response from listComputers query.
type ListComputersResponse struct {
	ListComputers struct {
		Items    []Computer `json:"items"`
		PageInfo struct {
			Next  *string `json:"next"`
			Total *int64  `json:"total"`
		} `json:"pageInfo"`
	} `json:"listComputers"`
}

// GetComputerResponse represents the response from getComputer query.
type GetComputerResponse struct {
	GetComputer *Computer `json:"getComputer"`
}

// ListComputers retrieves all computers from Jamf Protect.
func (s *Service) ListComputers(ctx context.Context) ([]Computer, error) {
	variables := mergeVars(map[string]any{
		"isList":    true,
		"nextToken": nil,
		"pageSize":  100,
		"direction": "ASC",
		"field":     []any{"hostName"},
		"filter":    nil,
	}, rbacComputer)

	var resp ListComputersResponse
	if err := s.client.DoGraphQL(ctx, "/app", listComputersQuery, variables, &resp); err != nil {
		return nil, fmt.Errorf("ListComputers: %w", err)
	}

	return resp.ListComputers.Items, nil
}

// GetComputer retrieves a single computer by UUID from Jamf Protect.
func (s *Service) GetComputer(ctx context.Context, uuid string) (*Computer, error) {
	variables := mergeVars(map[string]any{
		"uuid":   uuid,
		"isList": false,
	}, rbacComputer)

	var resp GetComputerResponse
	if err := s.client.DoGraphQL(ctx, "/app", getComputerQuery, variables, &resp); err != nil {
		return nil, fmt.Errorf("GetComputer(%s): %w", uuid, err)
	}

	return resp.GetComputer, nil
}
