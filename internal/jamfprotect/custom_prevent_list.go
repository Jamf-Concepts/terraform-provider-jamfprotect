// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

const customPreventListFields = `
fragment CustomPreventListFields on PreventList {
	id
	name
	description
	type
	tags
	list
	count
	created
}
`

const createCustomPreventListMutation = `
mutation createPreventList(
	$name: String!,
	$tags: [String]!,
	$type: PREVENT_LIST_TYPE!,
	$list: [String]!,
	$description: String
) {
	createPreventList(input: {
		name: $name,
		tags: $tags,
		type: $type,
		list: $list,
		description: $description
	}) {
		...CustomPreventListFields
	}
}
` + customPreventListFields

const getCustomPreventListQuery = `
query getPreventList($id: ID!) {
	getPreventList(id: $id) {
		...CustomPreventListFields
	}
}
` + customPreventListFields

const updateCustomPreventListMutation = `
mutation updatePreventList(
	$id: ID!,
	$name: String!,
	$tags: [String]!,
	$type: PREVENT_LIST_TYPE!,
	$list: [String]!,
	$description: String
) {
	updatePreventList(id: $id, input: {
		name: $name,
		tags: $tags,
		type: $type,
		list: $list,
		description: $description
	}) {
		...CustomPreventListFields
	}
}
` + customPreventListFields

const deleteCustomPreventListMutation = `
mutation deletePreventList($id: ID!) {
	deletePreventList(id: $id) {
		id
	}
}
`

const listCustomPreventListsQuery = `
query listPreventLists(
	$nextToken: String
	$direction: OrderDirection!
	$field: PreventListOrderField!
) {
	listPreventLists(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...CustomPreventListFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + customPreventListFields

// CustomPreventListInput is the create/update input for a custom prevent list.
type CustomPreventListInput struct {
	Name        string
	Description string
	Type        string
	Tags        []string
	List        []string
}

// CustomPreventList represents a custom prevent list.
type CustomPreventList struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Tags        []string `json:"tags"`
	List        []string `json:"list"`
	Count       int64    `json:"count"`
	Created     string   `json:"created"`
}

// CreateCustomPreventList creates a new custom prevent list.
func (s *Service) CreateCustomPreventList(ctx context.Context, input CustomPreventListInput) (CustomPreventList, error) {
	vars := map[string]any{
		"name":        input.Name,
		"tags":        input.Tags,
		"type":        input.Type,
		"list":        input.List,
		"description": input.Description,
	}
	var result struct {
		CreateCustomPreventList CustomPreventList `json:"createPreventList"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", createCustomPreventListMutation, vars, &result); err != nil {
		return CustomPreventList{}, err
	}
	return result.CreateCustomPreventList, nil
}

// GetCustomPreventList retrieves a custom prevent list by ID.
func (s *Service) GetCustomPreventList(ctx context.Context, id string) (*CustomPreventList, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetCustomPreventList *CustomPreventList `json:"getPreventList"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", getCustomPreventListQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetCustomPreventList, nil
}

// UpdateCustomPreventList updates an existing custom prevent list.
func (s *Service) UpdateCustomPreventList(ctx context.Context, id string, input CustomPreventListInput) (CustomPreventList, error) {
	vars := map[string]any{
		"id":          id,
		"name":        input.Name,
		"tags":        input.Tags,
		"type":        input.Type,
		"list":        input.List,
		"description": input.Description,
	}
	var result struct {
		UpdateCustomPreventList CustomPreventList `json:"updatePreventList"`
	}
	if err := s.client.DoGraphQL(ctx, "/graphql", updateCustomPreventListMutation, vars, &result); err != nil {
		return CustomPreventList{}, err
	}
	return result.UpdateCustomPreventList, nil
}

// DeleteCustomPreventList deletes a custom prevent list by ID.
func (s *Service) DeleteCustomPreventList(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, "/graphql", deleteCustomPreventListMutation, vars, nil)
}

// ListCustomPreventLists retrieves all custom prevent lists.
func (s *Service) ListCustomPreventLists(ctx context.Context) ([]CustomPreventList, error) {
	return client.ListAll[CustomPreventList](ctx, s.client, "/graphql", listCustomPreventListsQuery, map[string]any{
		"direction": "DESC",
		"field":     "created",
	}, "listPreventLists")
}
