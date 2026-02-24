# Repository Guidelines

## Overview

This is a Terraform provider for [Jamf Protect](https://www.jamf.com/products/jamf-protect/), built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 with Protocol v6. The Go module path is `github.com/Jamf-Concepts/terraform-provider-jamfprotect`.

## Tooling

- Use `make` for build, lint, test, and doc generation. See `GNUmakefile` for available targets.
- Go >= 1.26, Terraform >= 1.0.

### Available make targets

| Target     | Description                                           |
| ---------- | ----------------------------------------------------- |
| `build`    | Build the provider                                    |
| `install`  | Build and install the provider locally                |
| `fmt`      | Format Go source files                                |
| `lint`     | Run golangci-lint                                     |
| `generate` | Generate provider documentation with tfplugindocs     |
| `test`     | Run unit tests                                        |
| `testacc`  | Run acceptance tests (requires environment variables) |

The default target runs: `fmt lint install generate`.

## Jamf Protect API

- The Jamf Protect API exposes two GraphQL endpoints:
  - `/graphql` — limited scope, supports introspection.
  - `/app` — full API surface, introspection disabled. **The provider uses this endpoint for all operations.**
- Token endpoint: `POST ${JAMFPROTECT_URL}/token` with `client_id` + `password` fields -> returns `access_token` (no Bearer prefix). Tokens are cached for 25 minutes.

## Project Structure

```text
main.go                          # Provider entry point (registry.terraform.io/Jamf-Concepts/jamfprotect)
internal/
  client/                        # GraphQL transport client + auth + logging + sentinel errors
  common/
    constants/                   # Shared constants (timeouts, etc.)
    helpers/                     # Shared helper utilities
    validators/                  # Shared schema validators (UUID, resource name)
  jamfprotect/                   # Service layer built on the transport client
  provider/                      # Provider wiring + schema validation tests
  resources/                     # Per-resource packages (resource + data source)
    action_configuration/        # Reference implementation for complex resources
    analytic/
    analytic_set/
    api_client/
    change_management/
    computer/                    # Data source only (enrolled computers)
    custom_prevent_list/
    data_forwarding/
    data_retention/
    downloads/                   # Data source only (installer/profile download URLs)
    exception_set/
    group/
    identity_provider/           # Data source only (identity providers)
    plan/
    removable_storage_control_set/
    role/
    telemetry/
    unified_logging_filter/
    user/
  testutil/                      # Acceptance test helpers
tools/                           # Go generate tooling (tfplugindocs, copywrite)
docs/                            # Generated provider documentation (resources + data sources)
examples/
  resources/                     # Example .tf files for resources
  data-sources/                  # Example .tf files for data sources
  list-resources/                # Example .tf files for list resources
  provider/                      # Example provider configuration
templates/                       # tfplugindocs templates for doc generation
```

## Provider Development

- Terraform Plugin Framework code lives in `internal/`.
- The GraphQL client (`internal/client`) uses `sync.Mutex` for thread-safe token management and defines sentinel errors: `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound`.
- Resource implementations are grouped by package in `internal/resources/<resource>` with files split by concern (crud, helpers, resource, types, data source).
- Run formatting and linting before committing: `make fmt` and `make lint`.
- Generate docs with `make generate`.
- Run tests with `make test`; acceptance tests with `make testacc` (requires real tenant).

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
- Favor sets in resources for unordered data; use lists in data sources (Computed-only) for cheaper plan comparisons. Sort API responses in data source state builders.
- Favor nested attributes (set/single) instead of blocks wherever possible.

## Environment Variables

- `JAMFPROTECT_URL` — Base URL of the Jamf Protect tenant (e.g. `https://your-tenant.protect.jamfcloud.com`).
- `JAMFPROTECT_CLIENT_ID` — API client ID for authentication.
- `JAMFPROTECT_CLIENT_SECRET` — API client secret for authentication.
- These can also be set in the provider block in Terraform configuration.

## Testing

- **Unit tests**: `make test` — runs schema validation, metadata, plan modifier, state migration, flattener/expander, helper, and client tests (no real API needed).
- **Acceptance tests**: `make testacc` — creates real resources against a Jamf Protect tenant. Requires `JAMFPROTECT_URL`, `JAMFPROTECT_CLIENT_ID`, and `JAMFPROTECT_CLIENT_SECRET` environment variables.
- Test files follow the `*_test.go` convention next to the code they test.

## Adding a New Resource

1. Create a new package under `internal/resources/<resource_name>/` following the file conventions above.
2. Implement `resource.Resource` with CRUD + `ImportState` in `resource.go` and `crud.go`.
3. Register the resource in `internal/provider/provider.go` -> `Resources()`.
4. Add acceptance tests in `resource_test.go`.
5. Add schema validation tests in `internal/provider/schema_test.go`.
6. Add example `.tf` files under `examples/resources/<resource_name>/`.
7. Run `make test` to ensure tests pass.
8. Run `make generate` to generate documentation from schema descriptions.

## Documentation & Examples

- Update `examples/` when adding new resources or data sources.
- Run `make generate` to regenerate documentation from schema descriptions.
