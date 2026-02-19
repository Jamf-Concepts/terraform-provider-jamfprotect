# Repository Guidelines

## Overview

This is a Terraform provider for [Jamf Protect](https://www.jamf.com/products/jamf-protect/), built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 with Protocol v6. The Go module path is `github.com/smithjw/terraform-provider-jamfprotect`.

## Tooling

- Use `mise` for all toolchain setup and task execution. Run `mise run <task>` to execute tasks (auto-activates tools — no need for `eval "$(mise activate)"`).
- Go >= 1.25, Terraform >= 1.0.

### Available mise tasks

| Task                  | Description                                                 |
| --------------------- | ----------------------------------------------------------- |
| `install`             | Install Go module dependencies                              |
| `tidy`                | Tidy Go module dependencies                                 |
| `build`               | Build the provider and generate documentation (composite)   |
| `build:provider`      | Build the provider                                          |
| `build:generate-docs` | Generate provider documentation with tfplugindocs           |
| `dev:install`         | Build and install the provider locally (depends on `build`) |
| `fmt`                 | Format Go source files                                      |
| `lint`                | Run golangci-lint                                           |
| `test`                | Run unit tests                                              |
| `testacc`             | Run acceptance tests (requires environment variables)       |
| `check`               | Run fmt, lint, and unit tests (composite)                   |

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
- Captured queries and mutations from browser DevTools live in `graphql_api/` (operations covering ActionConfigurations, Analytic, AnalyticSets, ExceptionSets, Plan, CustomPreventList, TelemetryV2, USBControlSet, UnifiedLoggingFilter).

## Project Structure

```
main.go                          # Provider entry point (registry.terraform.io/smithjw/jamfprotect)
internal/
  client/                        # GraphQL transport client + auth + logging + sentinel errors
  common/
    constants/                   # Shared constants (timeouts, etc.)
    helpers/                     # Shared helper utilities
  jamfprotect/                   # Service layer built on the transport client
  provider/                      # Provider wiring + schema validation tests
  resources/                     # Per-resource packages (resource + data source)
    action_configuration/        # crud.go, data_source.go, input_builders.go, mappings.go, model_types.go, resource.go, schema_types.go, state_builders.go
    analytic/                     # crud.go, data_source.go, input_builders.go, mappings.go, model_types.go, resource.go, schema_types.go, state_builders.go
    analytic_set/                # crud.go, data_source.go, helpers.go, resource.go, types.go
    custom_prevent_list/         # crud.go, data_source.go, helpers.go, resource.go, types.go
    exception_set/               # crud.go, data_source.go, helpers.go, resource.go, types.go
    plan/                         # crud.go, data_source.go, helpers.go, resource.go, types.go
    removable_storage_control_set/ # crud.go, data_source.go, helpers.go, resource.go, types.go
    telemetry/                   # crud.go, data_source.go, helpers.go, resource.go, types.go
    unified_logging_filter/      # crud.go, data_source.go, helpers.go, resource.go, types.go
  testutil/                      # Acceptance test helpers
graphql_api/                     # Captured GraphQL operations (reference material)
tools/
  scripts/                       # Python helper scripts for API discovery
docs/                            # Generated provider documentation (resources + data sources)
examples/
  resources/                     # Example .tf files for resources
  data-sources/                  # Example .tf files for data sources
```

## Provider Development

- Terraform Plugin Framework code lives in `internal/`.
- The GraphQL client (`internal/client`) uses `sync.Mutex` for thread-safe token management and defines sentinel errors: `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound`.
- Resource implementations are grouped by package in `internal/resources/<resource>` with files split by concern (crud, helpers, resource, types, data source).
- Run formatting and linting before committing: `mise run fmt` and `mise run lint`.
- Generate docs with `mise run build:generate-docs`.
- Run tests with `mise run test`; acceptance tests with `mise run testacc` (requires real tenant).

## Code Organization Guidelines

- Look for opportunities to create reusable packages (helper/utility functions) instead of duplicating logic in resource packages.
- Keep packages split by concern with focused files (crud, helpers, resource, types, data source).
- Always look for existing helper functions that can be reused before adding new code.

## Code Style Guidelines

- Follow Go conventions and idiomatic patterns.
- Favor clear and descriptive naming for variables, functions, and types.
- Always ensure constants, functions, variable sets and types have a short comment describing their purpose.
- Do not add comments inside type definitions or function bodies.

### Resource Package File Conventions

Use resource-agnostic filenames and helper names so the same structure can apply to all resources:

- `resource.go`: schema and boilerplate.
- `crud.go`: Create/Read/Update/Delete and import.
- `model_types.go`: Terraform model structs only.
- `schema_types.go`: attr type maps used to build ObjectValue/ListValue state.
- `mappings.go`: lookup tables and name mappings.
- `input_builders.go`: build API inputs from Terraform model data.
- `state_builders.go`: map API responses to Terraform state.
- `helpers.go`: resource-specific helper functions that don't fit elsewhere.
- `plan_modifiers.go`: schema plan modifiers (if needed).
- `validators.go`: schema validators (if needed).
- `list_resource.go`: for list resources implementing `list.ListResource`.
- `data_source.go`: for data sources implementing `datasource.DataSource`.
- `resource_test.go`: acceptance tests for the resource.

For list resources, follow the framework list resource pattern. The action configuration list resource is the reference implementation.

Optional split-outs for complex resources:

- `endpoints_builders.go` and `endpoints_state.go` when endpoint logic dominates.
- `nested_builders.go` and `nested_state.go` for large nested payloads.

## Schema Guidelines

- Schemas should be inline and as flat as possible.
- Favor sets instead of lists unless sorting is absolutely necessary.
- Favor nested attributes (set/single) instead of blocks wherever possible.

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
6. Update `examples/` with example `.tf` files.
7. Run `mise run test` to ensure tests pass.
8. Run `mise run build:generate-docs` to generate documentation from schema descriptions.

## Documentation & Examples

- Update `examples/` when adding new resources or data sources.
- Run `mise run build:generate-docs` to regenerate documentation from schema descriptions.
