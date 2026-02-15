// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

const planFields = `
fragment PlanFields on Plan {
	id
	hash
	name
	description
	created
	updated
	logLevel
	autoUpdate
	commsConfig {
		fqdn
		protocol
	}
	infoSync {
		attrs
		insightsSyncInterval
	}
	signaturesFeedConfig {
		mode
	}
	actionConfigs {
		id
		name
	}
	exceptionSets {
		uuid
		name
		managed
	}
	usbControlSet {
		id
		name
	}
	telemetry {
		id
		name
	}
	telemetryV2 {
		id
		name
	}
	analyticSets {
		type
		analyticSet {
			uuid
			name
			managed
			analytics {
				uuid
				categories
			}
		}
	}
}
`

const createPlanMutation = `
mutation createPlan(
	$name: String!,
	$description: String!,
	$logLevel: LOG_LEVEL_ENUM,
	$actionConfigs: ID!,
	$exceptionSets: [ID!],
	$telemetry: ID,
	$telemetryV2: ID,
	$analyticSets: [PlanAnalyticSetInput!],
	$usbControlSet: ID,
	$commsConfig: CommsConfigInput!,
	$infoSync: InfoSyncInput!,
	$autoUpdate: Boolean!,
	$signaturesFeedConfig: SignaturesFeedConfigInput!
) {
	createPlan(input: {
		name: $name,
		description: $description,
		logLevel: $logLevel,
		actionConfigs: $actionConfigs,
		exceptionSets: $exceptionSets,
		telemetry: $telemetry,
		telemetryV2: $telemetryV2,
		analyticSets: $analyticSets,
		usbControlSet: $usbControlSet,
		commsConfig: $commsConfig,
		infoSync: $infoSync,
		autoUpdate: $autoUpdate,
		signaturesFeedConfig: $signaturesFeedConfig
	}) {
		...PlanFields
	}
}
` + planFields

const getPlanQuery = `
query getPlan($id: ID!) {
	getPlan(id: $id) {
		...PlanFields
	}
}
` + planFields

const updatePlanMutation = `
mutation updatePlan(
	$id: ID!,
	$name: String!,
	$description: String!,
	$logLevel: LOG_LEVEL_ENUM,
	$actionConfigs: ID!,
	$exceptionSets: [ID!],
	$telemetry: ID,
	$telemetryV2: ID,
	$analyticSets: [PlanAnalyticSetInput!],
	$usbControlSet: ID,
	$commsConfig: CommsConfigInput!,
	$infoSync: InfoSyncInput!,
	$autoUpdate: Boolean!,
	$signaturesFeedConfig: SignaturesFeedConfigInput!
) {
	updatePlan(id: $id, input: {
		name: $name,
		description: $description,
		logLevel: $logLevel,
		actionConfigs: $actionConfigs,
		exceptionSets: $exceptionSets,
		telemetry: $telemetry,
		telemetryV2: $telemetryV2,
		analyticSets: $analyticSets,
		usbControlSet: $usbControlSet,
		commsConfig: $commsConfig,
		infoSync: $infoSync,
		autoUpdate: $autoUpdate,
		signaturesFeedConfig: $signaturesFeedConfig
	}) {
		...PlanFields
	}
}
` + planFields

const deletePlanMutation = `
mutation deletePlan($id: ID!) {
	deletePlan(id: $id) {
		id
	}
}
`

const listPlansQuery = `
query listPlans($nextToken: String, $direction: OrderDirection!, $field: PlanOrderField!) {
	listPlans(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...PlanFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + planFields

// PlanAnalyticSetInput is a plan analytic set input entry.
type PlanAnalyticSetInput struct {
	Type string
	UUID string
}

// PlanCommsConfigInput captures communications configuration.
type PlanCommsConfigInput struct {
	FQDN     string
	Protocol string
}

// PlanInfoSyncInput captures info sync configuration.
type PlanInfoSyncInput struct {
	Attrs                []string
	InsightsSyncInterval int64
}

// PlanSignaturesFeedConfigInput captures signatures feed configuration.
type PlanSignaturesFeedConfigInput struct {
	Mode string
}

// PlanInput is the create/update input for a plan.
type PlanInput struct {
	Name                 string
	Description          string
	LogLevel             *string
	ActionConfigs        string
	ExceptionSets        []string
	Telemetry            *string
	TelemetryV2          *string
	TelemetryV2Null      bool
	AnalyticSets         []PlanAnalyticSetInput
	USBControlSet        *string
	CommsConfig          PlanCommsConfigInput
	InfoSync             PlanInfoSyncInput
	AutoUpdate           bool
	SignaturesFeedConfig PlanSignaturesFeedConfigInput
}

// Plan represents a Jamf Protect plan.
type Plan struct {
	ID                   string              `json:"id"`
	Hash                 string              `json:"hash"`
	Name                 string              `json:"name"`
	Description          string              `json:"description"`
	Created              string              `json:"created"`
	Updated              string              `json:"updated"`
	LogLevel             string              `json:"logLevel"`
	AutoUpdate           bool                `json:"autoUpdate"`
	CommsConfig          *PlanCommsConfig    `json:"commsConfig"`
	InfoSync             *PlanInfoSync       `json:"infoSync"`
	SignaturesFeedConfig *PlanSignaturesFeed `json:"signaturesFeedConfig"`
	ActionConfigs        *PlanRef            `json:"actionConfigs"`
	ExceptionSets        []PlanExceptionSet  `json:"exceptionSets"`
	USBControlSet        *PlanRef            `json:"usbControlSet"`
	Telemetry            *PlanRef            `json:"telemetry"`
	TelemetryV2          *PlanRef            `json:"telemetryV2"`
	AnalyticSets         []PlanAnalyticSet   `json:"analyticSets"`
}

// PlanCommsConfig represents comms config in a plan.
type PlanCommsConfig struct {
	FQDN     string `json:"fqdn"`
	Protocol string `json:"protocol"`
}

// PlanInfoSync represents info sync in a plan.
type PlanInfoSync struct {
	Attrs                []string `json:"attrs"`
	InsightsSyncInterval int64    `json:"insightsSyncInterval"`
}

// PlanSignaturesFeed represents signatures feed config in a plan.
type PlanSignaturesFeed struct {
	Mode string `json:"mode"`
}

// PlanRef represents an entity reference in a plan.
type PlanRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PlanExceptionSet represents an exception set in a plan.
type PlanExceptionSet struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

// PlanAnalyticSet represents an analytic set in a plan.
type PlanAnalyticSet struct {
	Type        string             `json:"type"`
	AnalyticSet PlanAnalyticSetRef `json:"analyticSet"`
}

// PlanAnalyticSetRef represents an analytic set reference.
type PlanAnalyticSetRef struct {
	UUID      string         `json:"uuid"`
	Name      string         `json:"name"`
	Managed   bool           `json:"managed"`
	Analytics []PlanAnalytic `json:"analytics"`
}

// PlanAnalytic represents analytic metadata on a plan analytic set.
type PlanAnalytic struct {
	UUID       string   `json:"uuid"`
	Categories []string `json:"categories"`
}

// CreatePlan creates a new plan.
func (s *Service) CreatePlan(ctx context.Context, input PlanInput) (Plan, error) {
	vars := buildPlanVariables(input)
	var result struct {
		CreatePlan Plan `json:"createPlan"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createPlanMutation, vars, &result); err != nil {
		return Plan{}, err
	}
	return result.CreatePlan, nil
}

// GetPlan retrieves a plan by ID.
func (s *Service) GetPlan(ctx context.Context, id string) (*Plan, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetPlan *Plan `json:"getPlan"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getPlanQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetPlan, nil
}

// UpdatePlan updates an existing plan.
func (s *Service) UpdatePlan(ctx context.Context, id string, input PlanInput) (Plan, error) {
	vars := buildPlanVariables(input)
	vars["id"] = id
	var result struct {
		UpdatePlan Plan `json:"updatePlan"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updatePlanMutation, vars, &result); err != nil {
		return Plan{}, err
	}
	return result.UpdatePlan, nil
}

// DeletePlan deletes a plan by ID.
func (s *Service) DeletePlan(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, "/app", deletePlanMutation, vars, nil)
}

// ListPlans retrieves all plans.
func (s *Service) ListPlans(ctx context.Context) ([]Plan, error) {
	allItems := make([]Plan, 0)
	var nextToken *string

	for {
		vars := map[string]any{
			"direction": "ASC",
			"field":     "CREATED",
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListPlans struct {
				Items    []Plan `json:"items"`
				PageInfo struct {
					Next  *string `json:"next"`
					Total int     `json:"total"`
				} `json:"pageInfo"`
			} `json:"listPlans"`
		}
		if err := s.client.DoGraphQL(ctx, "/app", listPlansQuery, vars, &result); err != nil {
			return nil, err
		}

		allItems = append(allItems, result.ListPlans.Items...)
		if result.ListPlans.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListPlans.PageInfo.Next
	}

	return allItems, nil
}

func buildPlanVariables(input PlanInput) map[string]any {
	vars := map[string]any{
		"name":          input.Name,
		"description":   input.Description,
		"actionConfigs": input.ActionConfigs,
		"autoUpdate":    input.AutoUpdate,
		"commsConfig": map[string]any{
			"fqdn":     input.CommsConfig.FQDN,
			"protocol": input.CommsConfig.Protocol,
		},
		"infoSync": map[string]any{
			"attrs":                input.InfoSync.Attrs,
			"insightsSyncInterval": input.InfoSync.InsightsSyncInterval,
		},
		"signaturesFeedConfig": map[string]any{
			"mode": input.SignaturesFeedConfig.Mode,
		},
	}

	if input.LogLevel != nil {
		vars["logLevel"] = *input.LogLevel
	}

	if input.ExceptionSets != nil {
		vars["exceptionSets"] = input.ExceptionSets
	}

	if input.Telemetry != nil {
		vars["telemetry"] = *input.Telemetry
	}

	if input.TelemetryV2Null {
		vars["telemetryV2"] = nil
	} else if input.TelemetryV2 != nil {
		vars["telemetryV2"] = *input.TelemetryV2
	}

	if input.AnalyticSets != nil {
		analyticSets := make([]map[string]any, 0, len(input.AnalyticSets))
		for _, set := range input.AnalyticSets {
			analyticSets = append(analyticSets, map[string]any{
				"type": set.Type,
				"uuid": set.UUID,
			})
		}
		vars["analyticSets"] = analyticSets
	}

	if input.USBControlSet != nil {
		vars["usbControlSet"] = *input.USBControlSet
	}

	return vars
}
