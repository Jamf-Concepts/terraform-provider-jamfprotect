// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

// exceptionSetFields defines the GraphQL fragment for exception set fields.
const exceptionSetFields = `
fragment ExceptionSetFields on ExceptionSet {
	uuid
	name
	description
	exceptions @skip(if: $minimal) {
		type
		value
		appSigningInfo {
			appId
			teamId
		}
		ignoreActivity
		analyticTypes
			analytic @include(if: $RBAC_Analytic) {
				name
				uuid
		}
	}
	esExceptions @skip(if: $minimal) {
		type
		value
		appSigningInfo {
			appId
			teamId
		}
		ignoreActivity
		ignoreListType
		ignoreListSubType
		eventType
	}
	created
	updated
	managed
}
`

// createExceptionSetMutation defines the GraphQL mutation for creating an exception set.
const createExceptionSetMutation = `
mutation createExceptionSet(
	$name: String!,
	$description: String,
	$exceptions: [ExceptionInput!]!,
	$esExceptions: [EsExceptionInput!]!,
	$minimal: Boolean!,
		$RBAC_Analytic: Boolean!
) {
	createExceptionSet(input: {
		name: $name,
		description: $description,
		exceptions: $exceptions,
		esExceptions: $esExceptions
	}) {
		...ExceptionSetFields
	}
}
` + exceptionSetFields

// getExceptionSetQuery defines the GraphQL query for retrieving an exception set.
const getExceptionSetQuery = `
query getExceptionSet(
	$uuid: ID!,
	$minimal: Boolean!,
		$RBAC_Analytic: Boolean!
) {
	getExceptionSet(uuid: $uuid) {
		...ExceptionSetFields
	}
}
` + exceptionSetFields

// updateExceptionSetMutation defines the GraphQL mutation for updating an exception set.
const updateExceptionSetMutation = `
mutation updateExceptionSet(
	$uuid: ID!,
	$name: String!,
	$description: String,
	$exceptions: [ExceptionInput!]!,
	$esExceptions: [EsExceptionInput!]!,
	$minimal: Boolean!,
		$RBAC_Analytic: Boolean!
) {
	updateExceptionSet(uuid: $uuid, input: {
		name: $name,
		description: $description,
		exceptions: $exceptions,
		esExceptions: $esExceptions
	}) {
		...ExceptionSetFields
	}
}
` + exceptionSetFields

// deleteExceptionSetMutation defines the GraphQL mutation for deleting an exception set.
const deleteExceptionSetMutation = `
mutation deleteExceptionSet($uuid: ID!) {
	deleteExceptionSet(uuid: $uuid) {
		uuid
	}
}
`

// listExceptionSetsQuery defines the GraphQL query for listing exception sets.
const listExceptionSetsQuery = `
query listExceptionSets($nextToken: String, $direction: OrderDirection = DESC, $field: ExceptionSetOrderField = created) {
	listExceptionSets(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			uuid
			name
			managed
		}
		pageInfo {
			next
			total
		}
	}
}
`

// ExceptionSetInput is the create/update input for an exception set.
type ExceptionSetInput struct {
	Name         string
	Description  string
	Exceptions   []ExceptionInput
	EsExceptions []EsExceptionInput
}

// AppSigningInfoInput represents app signing info in input.
type AppSigningInfoInput struct {
	AppId  string `json:"appId"`
	TeamId string `json:"teamId"`
}

// ExceptionInput represents an exception entry input.
type ExceptionInput struct {
	Type           string               `json:"type"`
	Value          string               `json:"value,omitempty"`
	AppSigningInfo *AppSigningInfoInput `json:"appSigningInfo,omitempty"`
	IgnoreActivity string               `json:"ignoreActivity"`
	AnalyticTypes  []string             `json:"analyticTypes,omitempty"`
	AnalyticUuid   string               `json:"analyticUuid,omitempty"`
}

// EsExceptionInput represents an ES exception entry input.
type EsExceptionInput struct {
	Type              string               `json:"type"`
	Value             string               `json:"value,omitempty"`
	AppSigningInfo    *AppSigningInfoInput `json:"appSigningInfo,omitempty"`
	IgnoreActivity    string               `json:"ignoreActivity"`
	IgnoreListType    string               `json:"ignoreListType,omitempty"`
	IgnoreListSubType string               `json:"ignoreListSubType,omitempty"`
	EventType         string               `json:"eventType,omitempty"`
}

// ExceptionSet represents an exception set.
type ExceptionSet struct {
	UUID         string        `json:"uuid"`
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Exceptions   []Exception   `json:"exceptions"`
	EsExceptions []EsException `json:"esExceptions"`
	Created      string        `json:"created"`
	Updated      string        `json:"updated"`
	Managed      bool          `json:"managed"`
}

// Exception represents an exception entry.
type Exception struct {
	Type           string          `json:"type"`
	Value          string          `json:"value"`
	AppSigningInfo *AppSigningInfo `json:"appSigningInfo"`
	IgnoreActivity string          `json:"ignoreActivity"`
	AnalyticTypes  []string        `json:"analyticTypes"`
	AnalyticUuid   string          `json:"analyticUuid"`
	Analytic       *AnalyticRef    `json:"analytic"`
}

// AnalyticRef represents an analytic reference on an exception.
type AnalyticRef struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// EsException represents an ES exception entry.
type EsException struct {
	Type              string          `json:"type"`
	Value             string          `json:"value"`
	AppSigningInfo    *AppSigningInfo `json:"appSigningInfo"`
	IgnoreActivity    string          `json:"ignoreActivity"`
	IgnoreListType    string          `json:"ignoreListType"`
	IgnoreListSubType string          `json:"ignoreListSubType"`
	EventType         string          `json:"eventType"`
}

// AppSigningInfo represents app signing info in responses.
type AppSigningInfo struct {
	AppId  string `json:"appId"`
	TeamId string `json:"teamId"`
}

// ExceptionSetListItem represents a list item for exception sets.
type ExceptionSetListItem struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

// CreateExceptionSet creates a new exception set.
func (s *Service) CreateExceptionSet(ctx context.Context, input ExceptionSetInput) (ExceptionSet, error) {
	vars := map[string]any{
		"name":          input.Name,
		"description":   input.Description,
		"exceptions":    input.Exceptions,
		"esExceptions":  input.EsExceptions,
		"minimal":       false,
		"RBAC_Analytic": true,
	}
	var result struct {
		CreateExceptionSet ExceptionSet `json:"createExceptionSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createExceptionSetMutation, vars, &result); err != nil {
		return ExceptionSet{}, err
	}
	return result.CreateExceptionSet, nil
}

// GetExceptionSet retrieves an exception set by UUID.
func (s *Service) GetExceptionSet(ctx context.Context, uuid string) (*ExceptionSet, error) {
	vars := map[string]any{
		"uuid":          uuid,
		"minimal":       false,
		"RBAC_Analytic": true,
	}
	var result struct {
		GetExceptionSet *ExceptionSet `json:"getExceptionSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getExceptionSetQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetExceptionSet, nil
}

// UpdateExceptionSet updates an existing exception set.
func (s *Service) UpdateExceptionSet(ctx context.Context, uuid string, input ExceptionSetInput) (ExceptionSet, error) {
	vars := map[string]any{
		"uuid":          uuid,
		"name":          input.Name,
		"description":   input.Description,
		"exceptions":    input.Exceptions,
		"esExceptions":  input.EsExceptions,
		"minimal":       false,
		"RBAC_Analytic": true,
	}
	var result struct {
		UpdateExceptionSet ExceptionSet `json:"updateExceptionSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateExceptionSetMutation, vars, &result); err != nil {
		return ExceptionSet{}, err
	}
	return result.UpdateExceptionSet, nil
}

// DeleteExceptionSet deletes an exception set by UUID.
func (s *Service) DeleteExceptionSet(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	return s.client.DoGraphQL(ctx, "/app", deleteExceptionSetMutation, vars, nil)
}

// ListExceptionSets retrieves all exception sets.
func (s *Service) ListExceptionSets(ctx context.Context) ([]ExceptionSetListItem, error) {
	return client.ListAll[ExceptionSetListItem](ctx, s.client, "/app", listExceptionSetsQuery, map[string]any{}, "listExceptionSets")
}
