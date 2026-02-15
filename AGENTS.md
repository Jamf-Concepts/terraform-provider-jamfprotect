# Repository Guidelines

## Overview

This is a Terraform provider for [Jamf Protect](https://www.jamf.com/products/jamf-protect/), built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 with Protocol v6. The Go module path is `github.com/smithjw/terraform-provider-jamfprotect`.

## Tooling

- Use `mise` for all toolchain setup and task execution. Run `mise run <task>` to execute tasks (auto-activates tools — no need for `eval "$(mise activate)"`).
- Go >= 1.25, Terraform >= 1.0.

### Available mise tasks

| Task                  | Description                                                          |
| --------------------- | -------------------------------------------------------------------- |
| `install`             | Install Go module dependencies                                       |
| `tidy`                | Tidy Go module dependencies                                         |
| `build`               | Build the provider and generate documentation (composite)            |
| `build:provider`      | Build the provider                                                   |
| `build:generate-docs` | Generate provider documentation with tfplugindocs                    |
| `dev:install`         | Build and install the provider locally (depends on `build`)          |
| `fmt`                 | Format Go source files                                               |
| `lint`                | Run golangci-lint                                                    |
| `test`                | Run unit tests                                                       |
| `testacc`             | Run acceptance tests (requires environment variables)                |
| `check`               | Run fmt, lint, and unit tests (composite)                            |

## Python Scripts

- Do not call `python` directly.
- Use `uv` with the script shebang format:
  `#!/usr/bin/env -S uv run --script` and inline frontmatter.
- Run scripts with `uv run path/to/script.py` or `uvx` for CLI tools.

## Jamf Protect API

- The Jamf Protect API exposes two GraphQL endpoints:
  - `/graphql` — limited scope, supports introspection.
  - `/app` — full API surface, introspection disabled. **The provider uses this endpoint for all operations.**
- Token endpoint: `POST ${JAMFPROTECT_URL}/token` with `client_id` + `password` fields → returns `access_token` (no Bearer prefix). Tokens are cached for 25 minutes.
- Helper scripts in `tools/scripts/`:
  - `introspect_jamfprotect_schema.py` — introspects `/graphql` for type discovery.
  - `describe_jamfprotect_graphql.py` — describes types from introspection output.
  - `mutation.py` — run arbitrary mutations against `/app`.
- Captured queries and mutations from browser DevTools live in `queries_and_mutations/` (operations covering ActionConfigs, Analytic, AnalyticSets, ExceptionSets, Plan, PreventList, TelemetryV2, USBControlSet, UnifiedLoggingFilter).

## Project Structure

```
main.go                          # Provider entry point (registry.terraform.io/smithjw/jamfprotect)
internal/
  graphql/
    client.go                    # Thread-safe GraphQL client with token caching & sentinel errors
    client_test.go               # Unit tests (httptest-based)
  provider/
    provider.go                  # JamfProtectProvider (url, client_id, client_secret)
    provider_test.go             # Provider acceptance test helpers
    helpers.go                   # listToStrings / stringsToList utilities
    helpers_test.go              # Helper unit tests
    schema_test.go               # Schema validation unit tests
    action_config_resource.go    # jamfprotect_action_config (CRUD + import)
    analytic_resource.go         # jamfprotect_analytic (CRUD + import)
    analytic_set_resource.go     # jamfprotect_analytic_set (CRUD + import)
    exception_set_resource.go    # jamfprotect_exception_set (CRUD + import)
    plan_resource.go             # jamfprotect_plan (CRUD + import)
    prevent_list_resource.go     # jamfprotect_prevent_list (CRUD + import)
    telemetry_v2_resource.go     # jamfprotect_telemetry_v2 (CRUD + import)
    unified_logging_filter_resource.go    # jamfprotect_unified_logging_filter (CRUD + import)
    removable_storage_control_set_resource.go  # jamfprotect_removable_storage_control_set (CRUD + import)
    *_types.go                   # Type definitions for each resource
    *_helpers.go                 # GraphQL queries and helper functions for each resource
    *_resource_test.go           # Acceptance tests for each resource
    plans_data_source.go         # jamfprotect_plans data source
    analytics_data_source.go     # jamfprotect_analytics data source
    analytic_sets_data_source.go # jamfprotect_analytic_sets data source
    exception_sets_data_source.go # jamfprotect_exception_sets data source
    action_configs_data_source.go        # jamfprotect_action_configs data source
    prevent_lists_data_source.go         # jamfprotect_prevent_lists data source
    telemetries_v2_data_source.go        # jamfprotect_telemetries_v2 data source
    unified_logging_filters_data_source.go  # jamfprotect_unified_logging_filters data source
    removable_storage_control_sets_data_source.go      # jamfprotect_removable_storage_control_sets data source
queries_and_mutations/           # Captured GraphQL operations (reference material)
tools/
  scripts/                       # Python helper scripts for API discovery
docs/                            # Generated provider documentation (resources + data sources)
examples/
  resources/                     # Example .tf files for resources
  data-sources/                  # Example .tf files for data sources
```

## Provider Development

- Terraform Plugin Framework code lives in `internal/`.
- The GraphQL client (`internal/graphql/client.go`) uses `sync.Mutex` for thread-safe token management and defines sentinel errors: `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound`.
- Run formatting and linting before committing: `mise run fmt` and `mise run lint`.
- Generate docs with `mise run build:generate-docs`.
- Run tests with `mise run test`; acceptance tests with `mise run testacc` (requires real tenant).

## Environment Variables

- `JAMFPROTECT_URL` — Base URL of the Jamf Protect tenant (e.g. `https://your-tenant.protect.jamfcloud.com`).
- `JAMFPROTECT_CLIENT_ID` — API client ID for authentication.
- `JAMFPROTECT_CLIENT_SECRET` — API client secret for authentication.
- These can also be set in the provider block in Terraform configuration.

## Testing

- **Unit tests**: `mise run test` — runs schema validation, helper, and client tests (no real API needed).
- **Acceptance tests**: `mise run testacc` — creates real resources against a Jamf Protect tenant. Requires `JAMFPROTECT_URL`, `JAMFPROTECT_CLIENT_ID`, and `JAMFPROTECT_CLIENT_SECRET` environment variables.
- Test files follow the `*_test.go` convention next to the code they test.

## Adding a New Resource

1. Capture the relevant GraphQL queries/mutations (see `queries_and_mutations/` for examples).
2. Create `internal/provider/<resource_name>_resource.go` implementing `resource.Resource` with CRUD + `ImportState`.
3. Register the resource in `provider.go` → `Resources()`.
4. Create `internal/provider/<resource_name>_resource_test.go` with acceptance tests.
5. Add schema validation tests in `schema_test.go`.
6. Update `docs/` and `examples/` with documentation and example `.tf` files.

## Documentation & Examples

- Update `docs/` and `examples/` when adding new resources or data sources.
- Run `mise run build:generate-docs` to regenerate documentation from schema descriptions.
