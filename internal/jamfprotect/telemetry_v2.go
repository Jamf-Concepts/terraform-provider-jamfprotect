// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

// telemetryV2Fields defines the GraphQL fragment for telemetry v2 fields.
const telemetryV2Fields = `
fragment TelemetryV2Fields on TelemetryV2 {
	id
	name
	description
	created
	updated
	logFiles
	logFileCollection
	performanceMetrics
	plans @include(if: $RBAC_Plan) {
		id
		name
	}
	events
	fileHashing
}
`

// createTelemetryV2Mutation defines the GraphQL mutation for creating telemetry v2.
const createTelemetryV2Mutation = `
mutation createTelemetryV2(
	$name: String!,
	$description: String,
	$logFiles: [String!]!,
	$logFileCollection: Boolean!,
	$performanceMetrics: Boolean!,
	$events: [ES_EVENTS_ENUM]!,
	$fileHashing: Boolean!,
	$RBAC_Plan: Boolean!
) {
	createTelemetryV2(
		input: {name: $name, description: $description, logFiles: $logFiles, logFileCollection: $logFileCollection, performanceMetrics: $performanceMetrics, events: $events, fileHashing: $fileHashing}
	) {
		...TelemetryV2Fields
	}
}

` + telemetryV2Fields

// getTelemetryV2Query defines the GraphQL query for retrieving telemetry v2 by ID.
const getTelemetryV2Query = `
	query getTelemetryV2($id: ID!, $RBAC_Plan: Boolean!) {
	getTelemetryV2(id: $id) {
		...TelemetryV2Fields
	}
}

` + telemetryV2Fields

// updateTelemetryV2Mutation defines the GraphQL mutation for updating telemetry v2.
const updateTelemetryV2Mutation = `
mutation updateTelemetryV2(
	$id: ID!,
	$name: String!,
	$description: String,
	$logFiles: [String!]!,
	$logFileCollection: Boolean!,
	$performanceMetrics: Boolean!,
	$events: [ES_EVENTS_ENUM]!,
	$fileHashing: Boolean!,
	$RBAC_Plan: Boolean!
) {
	updateTelemetryV2(
		id: $id
		input: {name: $name, description: $description, logFiles: $logFiles, logFileCollection: $logFileCollection, performanceMetrics: $performanceMetrics, events: $events, fileHashing: $fileHashing}
	) {
		...TelemetryV2Fields
	}
}

` + telemetryV2Fields

// deleteTelemetryV2Mutation defines the GraphQL mutation for deleting telemetry v2.
const deleteTelemetryV2Mutation = `
mutation deleteTelemetryV2($id: ID!) {
	deleteTelemetryV2(id: $id) {
		id
	}
}
`

// listTelemetriesV2Query defines the GraphQL query for listing telemetry v2.
const listTelemetriesV2Query = `
query listTelemetriesV2($nextToken: String, $direction: OrderDirection!, $field: TelemetryOrderField!, $RBAC_Plan: Boolean!) {
	listTelemetriesV2(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...TelemetryV2Fields
		}
		pageInfo {
			next
			total
		}
	}
}

` + telemetryV2Fields

// TelemetryV2Input is the create/update input for telemetry v2.
type TelemetryV2Input struct {
	Name               string
	Description        string
	LogFiles           []string
	LogFileCollection  bool
	PerformanceMetrics bool
	Events             []string
	FileHashing        bool
}

// TelemetryV2Plan represents a plan entry on telemetry v2.
type TelemetryV2Plan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TelemetryV2 represents a telemetry v2 configuration.
type TelemetryV2 struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Created            string            `json:"created"`
	Updated            string            `json:"updated"`
	LogFiles           []string          `json:"logFiles"`
	LogFileCollection  bool              `json:"logFileCollection"`
	PerformanceMetrics bool              `json:"performanceMetrics"`
	Plans              []TelemetryV2Plan `json:"plans"`
	Events             []string          `json:"events"`
	FileHashing        bool              `json:"fileHashing"`
}

// CreateTelemetryV2 creates a new telemetry v2 configuration.
func (s *Service) CreateTelemetryV2(ctx context.Context, input TelemetryV2Input) (TelemetryV2, error) {
	vars := map[string]any{
		"name":               input.Name,
		"description":        input.Description,
		"logFiles":           input.LogFiles,
		"logFileCollection":  input.LogFileCollection,
		"performanceMetrics": input.PerformanceMetrics,
		"events":             input.Events,
		"fileHashing":        input.FileHashing,
		"RBAC_Plan":          true,
	}
	var result struct {
		CreateTelemetryV2 TelemetryV2 `json:"createTelemetryV2"`
	}
	if err := s.client.DoGraphQL(ctx, createTelemetryV2Mutation, vars, &result); err != nil {
		return TelemetryV2{}, err
	}
	return result.CreateTelemetryV2, nil
}

// GetTelemetryV2 retrieves telemetry v2 by ID.
func (s *Service) GetTelemetryV2(ctx context.Context, id string) (*TelemetryV2, error) {
	vars := map[string]any{
		"id":        id,
		"RBAC_Plan": true,
	}
	var result struct {
		GetTelemetryV2 *TelemetryV2 `json:"getTelemetryV2"`
	}
	if err := s.client.DoGraphQL(ctx, getTelemetryV2Query, vars, &result); err != nil {
		return nil, err
	}
	return result.GetTelemetryV2, nil
}

// UpdateTelemetryV2 updates telemetry v2 by ID.
func (s *Service) UpdateTelemetryV2(ctx context.Context, id string, input TelemetryV2Input) (TelemetryV2, error) {
	vars := map[string]any{
		"id":                 id,
		"name":               input.Name,
		"description":        input.Description,
		"logFiles":           input.LogFiles,
		"logFileCollection":  input.LogFileCollection,
		"performanceMetrics": input.PerformanceMetrics,
		"events":             input.Events,
		"fileHashing":        input.FileHashing,
		"RBAC_Plan":          true,
	}
	var result struct {
		UpdateTelemetryV2 TelemetryV2 `json:"updateTelemetryV2"`
	}
	if err := s.client.DoGraphQL(ctx, updateTelemetryV2Mutation, vars, &result); err != nil {
		return TelemetryV2{}, err
	}
	return result.UpdateTelemetryV2, nil
}

// DeleteTelemetryV2 deletes telemetry v2 by ID.
func (s *Service) DeleteTelemetryV2(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, deleteTelemetryV2Mutation, vars, nil)
}

// ListTelemetriesV2 retrieves all telemetry v2 configurations.
func (s *Service) ListTelemetriesV2(ctx context.Context) ([]TelemetryV2, error) {
	var allItems []TelemetryV2
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "DESC",
			"field":     "created",
			"RBAC_Plan": true,
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListTelemetriesV2 struct {
				Items    []TelemetryV2 `json:"items"`
				PageInfo struct {
					Next  *string `json:"next"`
					Total int     `json:"total"`
				} `json:"pageInfo"`
			} `json:"listTelemetriesV2"`
		}
		if err := s.client.DoGraphQL(ctx, listTelemetriesV2Query, vars, &result); err != nil {
			return nil, err
		}

		allItems = append(allItems, result.ListTelemetriesV2.Items...)
		if result.ListTelemetriesV2.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListTelemetriesV2.PageInfo.Next
	}

	return allItems, nil
}
