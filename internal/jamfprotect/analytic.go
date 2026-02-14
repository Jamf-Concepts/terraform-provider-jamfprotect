// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

// analyticFields defines the GraphQL fragment for analytic fields.
const analyticFields = `
fragment AnalyticFields on Analytic {
    uuid
    name
    label
    inputType
    filter
    description
    longDescription
    created
    updated
    actions
    analyticActions {
        name
        parameters
    }
    tenantActions {
        name
        parameters
    }
    tags
    level
    severity
    tenantSeverity
    snapshotFiles
    context {
        name
        type
        exprs
    }
    categories
    jamf
    remediation
}
`

// createAnalyticMutation defines the GraphQL mutation for creating an analytic.
const createAnalyticMutation = `
mutation createAnalytic(
    $name: String!,
    $inputType: String!,
    $description: String!,
    $actions: [String],
    $analyticActions: [AnalyticActionsInput]!,
    $tags: [String]!,
    $categories: [String]!,
    $filter: String!,
    $context: [AnalyticContextInput]!,
    $level: Int!,
    $severity: SEVERITY!,
    $snapshotFiles: [String]!
) {
    createAnalytic(input: {
        name: $name,
        inputType: $inputType,
        description: $description,
        actions: $actions,
        analyticActions: $analyticActions,
        tags: $tags,
        categories: $categories,
        filter: $filter,
        context: $context,
        level: $level,
        severity: $severity,
        snapshotFiles: $snapshotFiles
    }) {
        ...AnalyticFields
    }
}
` + analyticFields

// getAnalyticQuery defines the GraphQL query for retrieving an analytic by UUID.
const getAnalyticQuery = `
query getAnalytic($uuid: ID!) {
    getAnalytic(uuid: $uuid) {
        ...AnalyticFields
    }
}
` + analyticFields

// updateAnalyticMutation defines the GraphQL mutation for updating an existing analytic.
const updateAnalyticMutation = `
mutation updateAnalytic(
    $uuid: ID!,
    $name: String!,
    $inputType: String!,
    $description: String!,
    $actions: [String],
    $analyticActions: [AnalyticActionsInput]!,
    $tags: [String]!,
    $categories: [String]!,
    $filter: String!,
    $context: [AnalyticContextInput]!,
    $level: Int!,
    $severity: SEVERITY,
    $snapshotFiles: [String]!
) {
    updateAnalytic(uuid: $uuid, input: {
        name: $name,
        inputType: $inputType,
        description: $description,
        actions: $actions,
        analyticActions: $analyticActions,
        categories: $categories,
        tags: $tags,
        filter: $filter,
        context: $context,
        level: $level,
        severity: $severity,
        snapshotFiles: $snapshotFiles
    }) {
        ...AnalyticFields
    }
}
` + analyticFields

// deleteAnalyticMutation defines the GraphQL mutation for deleting an analytic by UUID.
const deleteAnalyticMutation = `
mutation deleteAnalytic($uuid: ID!) {
    deleteAnalytic(uuid: $uuid) {
        uuid
    }
}
`

// listAnalyticsQuery defines the GraphQL query for listing all analytics.
const listAnalyticsQuery = `
query listAnalytics {
    listAnalytics {
        items {
            ...AnalyticFields
        }
        pageInfo {
            next
            total
        }
    }
}
` + analyticFields

// AnalyticInput is the create/update input for an analytic.
type AnalyticInput struct {
	Name            string
	InputType       string
	Description     string
	Actions         []string
	AnalyticActions []AnalyticActionInput
	Tags            []string
	Categories      []string
	Filter          string
	Context         []AnalyticContextInput
	Level           int64
	Severity        string
	SnapshotFiles   []string
}

// AnalyticActionInput represents an analytic action input.
type AnalyticActionInput struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

// AnalyticContextInput represents a context input.
type AnalyticContextInput struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}

// Analytic is the API representation of an analytic.
type Analytic struct {
	UUID            string            `json:"uuid"`
	Name            string            `json:"name"`
	Label           string            `json:"label"`
	InputType       string            `json:"inputType"`
	Filter          string            `json:"filter"`
	Description     string            `json:"description"`
	LongDescription string            `json:"longDescription"`
	Created         string            `json:"created"`
	Updated         string            `json:"updated"`
	Actions         []string          `json:"actions"`
	AnalyticActions []AnalyticAction  `json:"analyticActions"`
	TenantActions   []AnalyticAction  `json:"tenantActions"`
	Tags            []string          `json:"tags"`
	Level           int64             `json:"level"`
	Severity        string            `json:"severity"`
	TenantSeverity  string            `json:"tenantSeverity"`
	SnapshotFiles   []string          `json:"snapshotFiles"`
	Context         []AnalyticContext `json:"context"`
	Categories      []string          `json:"categories"`
	Jamf            bool              `json:"jamf"`
	Remediation     string            `json:"remediation"`
}

// AnalyticAction represents an analytic action.
type AnalyticAction struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

// AnalyticContext represents an analytic context entry.
type AnalyticContext struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}

// CreateAnalytic creates a new analytic.
func (s *Service) CreateAnalytic(ctx context.Context, input AnalyticInput) (Analytic, error) {
	vars := map[string]any{
		"name":            input.Name,
		"inputType":       input.InputType,
		"description":     input.Description,
		"actions":         input.Actions,
		"analyticActions": input.AnalyticActions,
		"tags":            input.Tags,
		"categories":      input.Categories,
		"filter":          input.Filter,
		"context":         input.Context,
		"level":           input.Level,
		"severity":        input.Severity,
		"snapshotFiles":   input.SnapshotFiles,
	}
	var result struct {
		CreateAnalytic Analytic `json:"createAnalytic"`
	}
	if err := s.client.DoGraphQL(ctx, createAnalyticMutation, vars, &result); err != nil {
		return Analytic{}, err
	}
	return result.CreateAnalytic, nil
}

// GetAnalytic retrieves an analytic by UUID.
func (s *Service) GetAnalytic(ctx context.Context, uuid string) (*Analytic, error) {
	vars := map[string]any{"uuid": uuid}
	var result struct {
		GetAnalytic *Analytic `json:"getAnalytic"`
	}
	if err := s.client.DoGraphQL(ctx, getAnalyticQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetAnalytic, nil
}

// UpdateAnalytic updates an existing analytic.
func (s *Service) UpdateAnalytic(ctx context.Context, uuid string, input AnalyticInput) (Analytic, error) {
	vars := map[string]any{
		"uuid":            uuid,
		"name":            input.Name,
		"inputType":       input.InputType,
		"description":     input.Description,
		"actions":         input.Actions,
		"analyticActions": input.AnalyticActions,
		"tags":            input.Tags,
		"categories":      input.Categories,
		"filter":          input.Filter,
		"context":         input.Context,
		"level":           input.Level,
		"severity":        input.Severity,
		"snapshotFiles":   input.SnapshotFiles,
	}
	var result struct {
		UpdateAnalytic Analytic `json:"updateAnalytic"`
	}
	if err := s.client.DoGraphQL(ctx, updateAnalyticMutation, vars, &result); err != nil {
		return Analytic{}, err
	}
	return result.UpdateAnalytic, nil
}

// DeleteAnalytic deletes an analytic by UUID.
func (s *Service) DeleteAnalytic(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	return s.client.DoGraphQL(ctx, deleteAnalyticMutation, vars, nil)
}

// ListAnalytics retrieves all analytics.
func (s *Service) ListAnalytics(ctx context.Context) ([]Analytic, error) {
	var result struct {
		ListAnalytics struct {
			Items []Analytic `json:"items"`
		} `json:"listAnalytics"`
	}
	if err := s.client.DoGraphQL(ctx, listAnalyticsQuery, nil, &result); err != nil {
		return nil, err
	}
	return result.ListAnalytics.Items, nil
}
