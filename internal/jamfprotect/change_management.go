// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

// changeManagementUpdateMutation defines the GraphQL mutation for config freeze updates.
const changeManagementUpdateMutation = `
mutation updateOrganizationConfigFreeze($configFreeze: Boolean!) {
	updateOrganizationConfigFreeze(input: {configFreeze: $configFreeze}) {
		configFreeze
	}
}
`

// changeManagementGetQuery defines the GraphQL query for current config freeze state.
const changeManagementGetQuery = `
query getConfigFreeze {
	getAppInitializationData {
		configFreeze
	}
}
`

// ChangeManagementConfig holds the config freeze setting.
type ChangeManagementConfig struct {
	ConfigFreeze bool `json:"configFreeze"`
}

// ChangeManagementConfigResult wraps config freeze query results.
type ChangeManagementConfigResult struct {
	GetAppInitializationData ChangeManagementConfig `json:"getAppInitializationData"`
}

// UpdateOrganizationConfigFreeze updates config freeze.
func (s *Service) UpdateOrganizationConfigFreeze(ctx context.Context, configFreeze bool) (ChangeManagementConfig, error) {
	vars := map[string]any{"configFreeze": configFreeze}
	var result struct {
		UpdateOrganizationConfigFreeze ChangeManagementConfig `json:"updateOrganizationConfigFreeze"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", changeManagementUpdateMutation, vars, &result); err != nil {
		return ChangeManagementConfig{}, err
	}
	return result.UpdateOrganizationConfigFreeze, nil
}

// GetConfigFreeze retrieves the current config freeze setting.
func (s *Service) GetConfigFreeze(ctx context.Context) (ChangeManagementConfig, error) {
	var result ChangeManagementConfigResult
	if err := s.client.DoGraphQL(ctx, "/app", changeManagementGetQuery, nil, &result); err != nil {
		return ChangeManagementConfig{}, err
	}
	return result.GetAppInitializationData, nil
}
