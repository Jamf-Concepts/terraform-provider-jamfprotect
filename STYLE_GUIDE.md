# Style Guide

Code style conventions for the Terraform Provider for Jamf Protect.

## Go Conventions

- Follow standard Go conventions and idiomatic patterns.
- Run `make fmt` and `make lint` before committing.
- Use clear, descriptive names for variables, functions, and types.
- Every exported constant, function, variable set, and type must have a short comment describing its purpose.
- Do not add comments inside type definitions or function bodies.

## Dependencies

Only use native Go, `golang.org/x` packages, and Terraform Plugin Framework packages. Do not introduce third-party dependencies without discussion.

## Resource Package File Conventions

Resource packages live under `internal/resources/<resource_name>/` and use resource-agnostic filenames:

| File                 | Purpose                                                   |
| -------------------- | --------------------------------------------------------- |
| `resource.go`        | Schema definition and boilerplate                         |
| `crud.go`            | Create, Read, Update, Delete, and ImportState             |
| `model_types.go`     | Terraform model structs                                   |
| `schema_types.go`    | Attribute type maps for `ObjectValue`/`ListValue` state   |
| `mappings.go`        | Lookup tables and name mappings                           |
| `input_builders.go`  | Build GraphQL mutation inputs from Terraform model data   |
| `state_builders.go`  | Map GraphQL responses to Terraform state                  |
| `helpers.go`         | Resource-specific helper functions                        |
| `plan_modifiers.go`  | Schema plan modifiers (if needed)                         |
| `validators.go`      | Schema validators (if needed)                             |
| `list_resource.go`   | List resource implementation                              |
| `data_source.go`     | Data source implementation                                |

### Optional split-outs for complex resources

- `endpoints_builders.go` / `endpoints_state.go` -- when endpoint logic dominates.
- `nested_builders.go` / `nested_state.go` -- for large nested payloads.

### Data-source-only packages

Packages that only contain a data source use `model_types.go` for their model structs and `data_source.go` for the implementation.

## Test File Conventions

| File                      | Purpose                                    |
| ------------------------- | ------------------------------------------ |
| `resource_test.go`        | Acceptance tests for the resource          |
| `data_source_test.go`     | Acceptance tests for the data source       |
| `helpers_test.go`         | Helper function tests                      |
| `input_builders_test.go`  | Input builder tests                        |
| `state_builders_test.go`  | State builder tests                        |
| `mappings_test.go`        | Mapping table tests                        |

Schema and metadata tests live in `internal/provider/schema_test.go`.

## Service Layer Conventions

The service layer in `internal/jamfprotect/` wraps the GraphQL client and provides typed CRUD methods per resource:

```go
func (s *Service) CreateActionConfig(ctx context.Context, input ActionConfigInput) (ActionConfig, error)
func (s *Service) GetActionConfig(ctx context.Context, id string) (*ActionConfig, error)
func (s *Service) UpdateActionConfig(ctx context.Context, id string, input ActionConfigInput) (ActionConfig, error)
func (s *Service) DeleteActionConfig(ctx context.Context, id string) error
func (s *Service) ListActionConfigs(ctx context.Context) ([]ActionConfigListItem, error)
```

Each service file contains the GraphQL queries/mutations as constants and the Go types for API request/response payloads.

## Schema Guidelines

- Keep schemas inline and as flat as possible.
- Favor nested attributes (`SingleNestedAttribute`, `SetNestedAttribute`, `ListNestedAttribute`) over blocks.

### Sets vs Lists

- **Sets** for user-supplied unordered collections where deduplication and order-independent comparison matter (e.g., `tags`, `list_data`, `analytic_sets`).
- **Lists** for computed API results that are read-only. Sets require element hashing which adds overhead with no benefit when the user doesn't control the values.

Data source attributes returning API data should always use lists. Sort API responses in data source state builders.

## Error Handling

- Use `helpers.IsNotFoundError(err)` for 404 detection in Read/Delete operations.
- Wrap errors with `fmt.Errorf("context: %w", err)` to preserve the error chain.
- The GraphQL client defines sentinel errors: `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound`.

## Naming Patterns

### Resources

Terraform resource type names follow `jamfprotect_<resource>`:

- `jamfprotect_action_configuration`
- `jamfprotect_analytic`
- `jamfprotect_plan`
- `jamfprotect_custom_prevent_list`

### Test names

Test functions use the pattern `TestAcc<Resource>Resource_<scenario>` for acceptance tests and `Test<Function>_<case>` for unit tests:

```go
func TestAccActionConfigResource_basic(t *testing.T) { ... }
func TestAccAnalyticResource_basic(t *testing.T) { ... }
func TestSplitExtendedDataAttributes(t *testing.T) { ... }
```

### Acceptance test resource names

Use the `tf-acc-` prefix for all resources created during acceptance tests:

```go
rName := acctest.RandomWithPrefix("tf-acc-ac")
rName := acctest.RandomWithPrefix("tf-acc-analytic")
```
