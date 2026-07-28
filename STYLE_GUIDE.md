# Style Guide

Code style conventions for the Terraform Provider for Jamf Protect.

## Go Conventions

- Follow standard Go conventions and idiomatic patterns.
- Run `make fmt` and `make lint` before committing.
- Use clear, descriptive names for variables, functions, and types.
- Every exported constant, function, variable set, and type must have a short comment describing its purpose.
- Do not add comments inside type definitions or function bodies.

## Dependencies

Only use native Go, `golang.org/x` packages, the [Jamf Protect Go SDK](https://github.com/Jamf-Concepts/jamfprotect-go-sdk), and Terraform Plugin Framework packages. Do not introduce third-party dependencies without discussion.

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

## Action Package File Conventions

[Actions](https://developer.hashicorp.com/terraform/plugin/framework/actions) model imperative operations the provider does not own the lifecycle of — where a managed resource would fight the system of record on every reconcile. Action packages live under `internal/actions/<domain>/`, named `<domain>actions` (for example `internal/actions/computer/` is `package computeractions`), with one file per action:

| File                    | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `<action_name>.go`      | One action: type, model struct, Metadata, Schema, Invoke        |
| `helpers.go`            | Package doc, shared Configure/client handling, shared attributes |
| `validators.go`         | `action.ConfigValidator` and schema validators                  |
| `action_test.go`        | Acceptance tests for the package's actions                      |
| `helpers_test.go`       | Helper function tests                                           |
| `validators_test.go`    | Validator tests                                                 |

- Name the action type after the underlying API operation (GraphQL `setComputerPlan` becomes `jamfprotect_set_computer_plan`), so it maps mechanically onto its Jamf Platform counterpart when these move to the `jamfplatform` provider.
- Open `helpers.go` with a package doc block listing the SDK methods the actions call, mirroring the resource packages' service-layer contract.
- Report progress with `resp.SendProgress` around each API call — an action produces no state, so progress events are the only feedback a practitioner gets.
- Actions that operate on a collection take a single required set of targets rather than a set plus a scalar convenience attribute — a one-element set covers the single-target case without a `ConfigValidator` to enforce exclusivity. An empty set is a no-op with a warning, never an error, so a pipeline stays re-runnable once the fleet already matches.
- Already-gone targets warn rather than error, for the same reason.
- Aggregate per-target failures into a single error diagnostic listing every failure, rather than stopping at the first.
- Actions require Terraform 1.14, which has no destroy-time events (`before_destroy` / `after_destroy` fail validation). Document direct invocation (`terraform apply -invoke=action.<type>.<name>`) as the primary workflow and `lifecycle.action_trigger` as the secondary one.
- Destructive actions state the consequence and its limits in the schema description with a `~>` callout; they do not add a confirmation attribute.

## Test File Conventions

| File                      | Purpose                                    |
| ------------------------- | ------------------------------------------ |
| `resource_test.go`        | Acceptance tests for the resource          |
| `data_source_test.go`     | Acceptance tests for the data source       |
| `action_test.go`          | Acceptance tests for actions               |
| `helpers_test.go`         | Helper function tests                      |
| `input_builders_test.go`  | Input builder tests                        |
| `state_builders_test.go`  | State builder tests                        |
| `mappings_test.go`        | Mapping table tests                        |

Schema and metadata tests live in `internal/provider/schema_test.go`.

Acceptance tests that invoke an action need a resource carrying a `lifecycle.action_trigger` (`terraform_data` works), and a `tfversion.SkipBelow(tfversion.Version1_14_0)` version check. Gate anything that mutates the fleet behind its own environment variable so the default `make testacc` run only exercises validation.

## Service Layer

The provider uses the [Jamf Protect Go SDK](https://github.com/Jamf-Concepts/jamfprotect-go-sdk) (`jamfprotect.Client`) for all API operations. The SDK handles authentication, GraphQL transport, and provides typed CRUD methods per resource. Sentinel errors (`ErrAuthentication`, `ErrGraphQL`, `ErrNotFound`) are defined by the SDK.

## Schema Guidelines

- Keep schemas inline and as flat as possible.
- Favor nested attributes (`SingleNestedAttribute`, `SetNestedAttribute`, `ListNestedAttribute`) over blocks.

### Write-only attributes for one-way (write-only) API values

Any value the API accepts on a mutation but never returns on read (secrets, tokens, passwords) must be exposed as a [write-only argument](https://developer.hashicorp.com/terraform/language/resources/ephemeral#write-only-arguments) (`WriteOnly: true`, Terraform 1.11+), so the value is never persisted to state.

- Name the attribute with a `_wo` suffix and pair it with a `_wo_version` attribute. Bumping the version is the only way to push a rotated value, since the write-only value itself produces no plan diff.
- Read the value from the request config (`req.Config`) in Create/Update — it is absent from plan and state. Never write it back to state.
- Bind the pair with `AlsoRequires` (both directions) and any pre-existing plaintext attribute with `ConflictsWith`.
- When replacing a plaintext attribute, mark the old attribute `DeprecationMessage` with the date deprecated rather than removing it outright.

### Sets vs Lists

- **Sets** for user-supplied unordered collections where deduplication and order-independent comparison matter (e.g., `tags`, `list_data`, `analytic_sets`).
- **Lists** for computed API results that are read-only. Sets require element hashing which adds overhead with no benefit when the user doesn't control the values.

Data source attributes returning API data should always use lists. Sort API responses in data source state builders.

## Error Handling

- Use `common.IsNotFoundError(err)` for 404 detection in Read/Delete operations (imported as `common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"`). This wraps the SDK's `jamfprotect.ErrNotFound`.
- Wrap errors with `fmt.Errorf("context: %w", err)` to preserve the error chain.
- The SDK defines sentinel errors: `jamfprotect.ErrAuthentication`, `jamfprotect.ErrGraphQL`, `jamfprotect.ErrNotFound`.

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
