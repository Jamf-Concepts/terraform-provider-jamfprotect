// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

// unifiedLoggingFilterFields defines the GraphQL fragment for unified logging filter fields.
const unifiedLoggingFilterFields = `
fragment UnifiedLoggingFilterFields on UnifiedLoggingFilter {
	uuid
	name
	description
	created
	updated
	filter
	tags
	enabled
}
`

// createUnifiedLoggingFilterMutation defines the GraphQL mutation for creating a unified logging filter.
const createUnifiedLoggingFilterMutation = `
mutation createUnifiedLoggingFilter(
	$name: String!,
	$description: String,
	$tags: [String]!,
	$filter: String!,
	$enabled: Boolean
) {
	createUnifiedLoggingFilter(
		input: {name: $name, description: $description, tags: $tags, filter: $filter, enabled: $enabled}
	) {
		...UnifiedLoggingFilterFields
	}
}

` + unifiedLoggingFilterFields

// getUnifiedLoggingFilterQuery defines the GraphQL query for retrieving a unified logging filter by UUID.
const getUnifiedLoggingFilterQuery = `
query getUnifiedLoggingFilter($uuid: ID!) {
	getUnifiedLoggingFilter(uuid: $uuid) {
		...UnifiedLoggingFilterFields
	}
}

` + unifiedLoggingFilterFields

// updateUnifiedLoggingFilterMutation defines the GraphQL mutation for updating a unified logging filter.
const updateUnifiedLoggingFilterMutation = `
mutation updateUnifiedLoggingFilter(
	$uuid: ID!,
	$name: String!,
	$description: String,
	$filter: String!,
	$tags: [String]!,
	$enabled: Boolean
) {
	updateUnifiedLoggingFilter(
		uuid: $uuid
		input: {name: $name, description: $description, filter: $filter, tags: $tags, enabled: $enabled}
	) {
		...UnifiedLoggingFilterFields
	}
}

` + unifiedLoggingFilterFields

// deleteUnifiedLoggingFilterMutation defines the GraphQL mutation for deleting a unified logging filter.
const deleteUnifiedLoggingFilterMutation = `
mutation deleteUnifiedLoggingFilter($uuid: ID!) {
	deleteUnifiedLoggingFilter(uuid: $uuid) {
		uuid
	}
}
`

// listUnifiedLoggingFiltersQuery defines the GraphQL query for listing unified logging filters.
const listUnifiedLoggingFiltersQuery = `
query listUnifiedLoggingFilters($nextToken: String, $direction: OrderDirection!, $field: UnifiedLoggingFiltersOrderField!, $filter: UnifiedLoggingFiltersFilterInput!) {
	listUnifiedLoggingFilters(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100, filter: $filter}
	) {
		items {
			...UnifiedLoggingFilterFields
		}
		pageInfo {
		next
		total
		}
	}
}

` + unifiedLoggingFilterFields

// UnifiedLoggingFilterInput is the create/update input for a unified logging filter.
type UnifiedLoggingFilterInput struct {
	Name        string
	Description string
	Tags        []string
	Filter      string
	Enabled     bool
}

// UnifiedLoggingFilter represents a unified logging filter.
type UnifiedLoggingFilter struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Filter      string   `json:"filter"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
}

// CreateUnifiedLoggingFilter creates a new unified logging filter.
func (s *Service) CreateUnifiedLoggingFilter(ctx context.Context, input UnifiedLoggingFilterInput) (UnifiedLoggingFilter, error) {
	vars := map[string]any{
		"name":        input.Name,
		"description": input.Description,
		"tags":        input.Tags,
		"filter":      input.Filter,
		"enabled":     input.Enabled,
	}
	var result struct {
		CreateUnifiedLoggingFilter UnifiedLoggingFilter `json:"createUnifiedLoggingFilter"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", createUnifiedLoggingFilterMutation, vars, &result); err != nil {
		return UnifiedLoggingFilter{}, err
	}
	return result.CreateUnifiedLoggingFilter, nil
}

// GetUnifiedLoggingFilter retrieves a unified logging filter by UUID.
func (s *Service) GetUnifiedLoggingFilter(ctx context.Context, uuid string) (*UnifiedLoggingFilter, error) {
	vars := map[string]any{"uuid": uuid}
	var result struct {
		GetUnifiedLoggingFilter *UnifiedLoggingFilter `json:"getUnifiedLoggingFilter"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", getUnifiedLoggingFilterQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetUnifiedLoggingFilter, nil
}

// UpdateUnifiedLoggingFilter updates a unified logging filter.
func (s *Service) UpdateUnifiedLoggingFilter(ctx context.Context, uuid string, input UnifiedLoggingFilterInput) (UnifiedLoggingFilter, error) {
	vars := map[string]any{
		"uuid":        uuid,
		"name":        input.Name,
		"description": input.Description,
		"tags":        input.Tags,
		"filter":      input.Filter,
		"enabled":     input.Enabled,
	}
	var result struct {
		UpdateUnifiedLoggingFilter UnifiedLoggingFilter `json:"updateUnifiedLoggingFilter"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", updateUnifiedLoggingFilterMutation, vars, &result); err != nil {
		return UnifiedLoggingFilter{}, err
	}
	return result.UpdateUnifiedLoggingFilter, nil
}

// DeleteUnifiedLoggingFilter deletes a unified logging filter by UUID.
func (s *Service) DeleteUnifiedLoggingFilter(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	return s.client.DoGraphQL(ctx, "/graphql", deleteUnifiedLoggingFilterMutation, vars, nil)
}

// ListUnifiedLoggingFilters retrieves all unified logging filters.
func (s *Service) ListUnifiedLoggingFilters(ctx context.Context) ([]UnifiedLoggingFilter, error) {
	return client.ListAll[UnifiedLoggingFilter](ctx, s.client, "/graphql", listUnifiedLoggingFiltersQuery, map[string]any{
		"direction": "ASC",
		"field":     "name",
		"filter":    map[string]any{},
	}, "listUnifiedLoggingFilters")
}
