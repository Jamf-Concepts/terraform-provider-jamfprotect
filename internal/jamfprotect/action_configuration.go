// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

// actionConfigFields defines the GraphQL fragment for action configuration fields.
const actionConfigFields = `
fragment ActionConfigsFields on ActionConfigs {
    id
    name
    description
    hash
    created
    updated
    alertConfig {
        data {
            binary { attrs related }
            clickEvent { attrs related }
            downloadEvent { attrs related }
            file { attrs related }
            fsEvent { attrs related }
            group { attrs related }
            procEvent { attrs related }
            process { attrs related }
            screenshotEvent { attrs related }
            usbEvent { attrs related }
            user { attrs related }
            gkEvent { attrs related }
            keylogRegisterEvent { attrs related }
            mrtEvent { attrs related }
        }
    }
    clients {
        id
        type
        supportedReports
        batchConfig {
            delimiter
            sizeIndex
            windowInSeconds
            sizeInBytes
        }
        params {
            ... on JamfCloudClientParams { destinationFilter }
            ... on HttpClientParams { headers { header value } method url }
            ... on KafkaClientParams { host port topic clientCN serverCN }
            ... on SyslogClientParams { host port scheme }
            ... on LogFileClientParams { path permissions maxSizeMB ownership backups }
        }
    }
}
`

// createActionConfigMutation defines the GraphQL mutation for creating an action configuration.
const createActionConfigMutation = `
mutation createActionConfigs(
    $name: String!,
    $description: String!,
    $alertConfig: ActionConfigsAlertConfigInput!,
    $clients: [ReportClientInput!]
) {
    createActionConfigs(input: {
        name: $name,
        description: $description,
        alertConfig: $alertConfig,
        clients: $clients
    }) {
        ...ActionConfigsFields
    }
}
` + actionConfigFields

// getActionConfigQuery defines the GraphQL query for retrieving an action configuration by ID.
const getActionConfigQuery = `
query getActionConfigs($id: ID!) {
    getActionConfigs(id: $id) {
        ...ActionConfigsFields
    }
}
` + actionConfigFields

// updateActionConfigMutation defines the GraphQL mutation for updating an existing action configuration.
const updateActionConfigMutation = `
mutation updateActionConfigs(
    $id: ID!,
    $name: String!,
    $description: String!,
    $alertConfig: ActionConfigsAlertConfigInput!,
    $clients: [ReportClientInput!]
) {
    updateActionConfigs(id: $id, input: {
        name: $name,
        description: $description,
        alertConfig: $alertConfig,
        clients: $clients
    }) {
        ...ActionConfigsFields
    }
}
` + actionConfigFields

// deleteActionConfigMutation defines the GraphQL mutation for deleting an action configuration by ID.
const deleteActionConfigMutation = `
mutation deleteActionConfigs($id: ID!) {
    deleteActionConfigs(id: $id) {
        id
    }
}
`

// listActionConfigsQuery defines the GraphQL query for listing all action configurations with pagination support.
const listActionConfigsQuery = `
query listActionConfigs($nextToken: String, $direction: OrderDirection!, $field: ActionConfigsOrderField!) {
    listActionConfigs(
        input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
    ) {
        items {
            id
            name
            description
            created
            updated
        }
        pageInfo {
            next
            total
        }
    }
}
`

// ActionConfigInput is the create/update input for an action configuration.
type ActionConfigInput struct {
	Name        string
	Description string
	AlertConfig map[string]any
	Clients     []map[string]any
}

// ActionConfig is the API representation of an action configuration.
type ActionConfig struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Hash        string         `json:"hash"`
	Created     string         `json:"created"`
	Updated     string         `json:"updated"`
	AlertConfig *AlertConfig   `json:"alertConfig"`
	Clients     []ReportClient `json:"clients"`
}

// ActionConfigListItem is the list view for action configurations.
type ActionConfigListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
}

// AlertConfig maps alert configuration data for action configs.
type AlertConfig struct {
	Data *AlertData `json:"data"`
}

// AlertData contains event-type alert enrichment configuration.
type AlertData struct {
	Binary              *AlertEventType `json:"binary"`
	ClickEvent          *AlertEventType `json:"clickEvent"`
	DownloadEvent       *AlertEventType `json:"downloadEvent"`
	File                *AlertEventType `json:"file"`
	FsEvent             *AlertEventType `json:"fsEvent"`
	Group               *AlertEventType `json:"group"`
	ProcEvent           *AlertEventType `json:"procEvent"`
	Process             *AlertEventType `json:"process"`
	ScreenshotEvent     *AlertEventType `json:"screenshotEvent"`
	UsbEvent            *AlertEventType `json:"usbEvent"`
	User                *AlertEventType `json:"user"`
	GkEvent             *AlertEventType `json:"gkEvent"`
	KeylogRegisterEvent *AlertEventType `json:"keylogRegisterEvent"`
	MrtEvent            *AlertEventType `json:"mrtEvent"`
}

// AlertEventType describes an event type's included attributes and related objects.
type AlertEventType struct {
	Attrs   []string `json:"attrs"`
	Related []string `json:"related"`
}

// ReportClient represents a reporting client configuration.
type ReportClient struct {
	ID               string             `json:"id"`
	Type             string             `json:"type"`
	SupportedReports []string           `json:"supportedReports"`
	BatchConfig      *BatchConfig       `json:"batchConfig"`
	Params           ReportClientParams `json:"params"`
}

// BatchConfig represents batching configuration for a report client.
type BatchConfig struct {
	Delimiter       string `json:"delimiter"`
	SizeIndex       int64  `json:"sizeIndex"`
	WindowInSeconds int64  `json:"windowInSeconds"`
	SizeInBytes     int64  `json:"sizeInBytes"`
}

// ReportClientParams represents endpoint-specific parameters for a report client.
type ReportClientParams struct {
	DestinationFilter string               `json:"destinationFilter"`
	Headers           []ReportClientHeader `json:"headers"`
	Method            string               `json:"method"`
	URL               string               `json:"url"`
	Host              string               `json:"host"`
	Port              int64                `json:"port"`
	Topic             string               `json:"topic"`
	ClientCN          string               `json:"clientCN"`
	ServerCN          string               `json:"serverCN"`
	Scheme            string               `json:"scheme"`
	Path              string               `json:"path"`
	Permissions       string               `json:"permissions"`
	MaxSizeMB         int64                `json:"maxSizeMB"`
	Ownership         string               `json:"ownership"`
	Backups           int64                `json:"backups"`
}

// ReportClientHeader represents a header entry for HTTP-based clients.
type ReportClientHeader struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

// CreateActionConfig creates a new action configuration.
func (s *Service) CreateActionConfig(ctx context.Context, input ActionConfigInput) (ActionConfig, error) {
	vars := map[string]any{
		"name":        input.Name,
		"description": input.Description,
		"alertConfig": input.AlertConfig,
		"clients":     input.Clients,
	}
	var result struct {
		CreateActionConfigs ActionConfig `json:"createActionConfigs"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createActionConfigMutation, vars, &result); err != nil {
		return ActionConfig{}, err
	}
	return result.CreateActionConfigs, nil
}

// GetActionConfig retrieves an action configuration by ID.
func (s *Service) GetActionConfig(ctx context.Context, id string) (*ActionConfig, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetActionConfigs *ActionConfig `json:"getActionConfigs"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getActionConfigQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetActionConfigs, nil
}

// UpdateActionConfig updates an existing action configuration.
func (s *Service) UpdateActionConfig(ctx context.Context, id string, input ActionConfigInput) (ActionConfig, error) {
	vars := map[string]any{
		"id":          id,
		"name":        input.Name,
		"description": input.Description,
		"alertConfig": input.AlertConfig,
		"clients":     input.Clients,
	}
	var result struct {
		UpdateActionConfigs ActionConfig `json:"updateActionConfigs"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateActionConfigMutation, vars, &result); err != nil {
		return ActionConfig{}, err
	}
	return result.UpdateActionConfigs, nil
}

// DeleteActionConfig deletes an action configuration by ID.
func (s *Service) DeleteActionConfig(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, "/app", deleteActionConfigMutation, vars, nil)
}

// ListActionConfigs retrieves all action configurations.
func (s *Service) ListActionConfigs(ctx context.Context) ([]ActionConfigListItem, error) {
	var allItems []ActionConfigListItem
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "DESC",
			"field":     "created",
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListActionConfigs struct {
				Items    []ActionConfigListItem `json:"items"`
				PageInfo struct {
					Next  *string `json:"next"`
					Total int     `json:"total"`
				} `json:"pageInfo"`
			} `json:"listActionConfigs"`
		}
		if err := s.client.DoGraphQL(ctx, "/app", listActionConfigsQuery, vars, &result); err != nil {
			return nil, err
		}

		allItems = append(allItems, result.ListActionConfigs.Items...)
		if result.ListActionConfigs.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListActionConfigs.PageInfo.Next
	}

	return allItems, nil
}
