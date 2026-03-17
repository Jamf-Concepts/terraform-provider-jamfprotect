# Testing

This document covers the testing strategy and instructions for the Terraform Provider for Jamf Protect.

## Test Categories

| Category   | Requires API | Command         |
| ---------- | ------------ | --------------- |
| Unit       | No           | `make test`     |
| Acceptance | Yes          | `make testacc`  |

### Unit Tests

Unit tests validate schema definitions, metadata, plan modifiers, state builders, input builders, helper functions, mappings, validators, and client HTTP behaviour using a mock server. They do not require network access or API credentials.

```bash
make test
```

### Acceptance Tests

Acceptance tests create, read, update, and delete real resources against a live Jamf Protect tenant. They are gated behind the `TF_ACC=1` environment variable so they never run by default.

```bash
export JAMFPROTECT_URL="https://your-tenant.protect.jamfcloud.com"
export JAMFPROTECT_CLIENT_ID="your-client-id"
export JAMFPROTECT_CLIENT_SECRET="your-client-secret"

make testacc
```

**Flags explained:**

- `TF_ACC=1` enables acceptance tests (standard Terraform SDK convention).
- `-p=1` runs packages sequentially to avoid concurrent token issues with the Jamf Protect API.
- `-count=1` bypasses the Go test cache (useful for re-runs).

## Test File Layout

Test files live alongside the code they test, following Go convention:

```text
internal/
├── common/
│   ├── helpers/helpers_test.go         # Unit: shared helpers
│   └── validators/
│       ├── resource_name_test.go       # Unit: resource name validator
│       └── uuid_test.go               # Unit: UUID validator
├── provider/
│   └── schema_test.go                  # Unit: schema and metadata validation for all resources/data sources
├── resources/
│   ├── action_configuration/
│   │   ├── resource_test.go            # Acceptance: full CRUD
│   │   ├── input_builders_test.go      # Unit: input builder tests
│   │   └── mappings_test.go            # Unit: mapping table tests
│   ├── analytic/
│   │   ├── resource_test.go
│   │   └── mappings_test.go
│   ├── plan/
│   │   ├── resource_test.go
│   │   ├── helpers_test.go
│   │   └── mappings_test.go
│   └── ...
└── testutil/
    └── testutil.go                     # Acceptance test helpers
```

### Naming conventions

- `*_test.go` -- unit and acceptance tests (same file, no build tags).
- Schema and metadata tests live centrally in `internal/provider/schema_test.go`.
- Acceptance tests use `TestAcc` prefix (e.g., `TestAccActionConfigResource_basic`).
- Unit tests use `Test` prefix (e.g., `TestSplitExtendedDataAttributes`).

## Writing Unit Tests

Unit tests use Go's standard `testing` package. Client tests use `httptest.NewServer` to mock the Jamf Protect GraphQL API.

```go
func TestMyFunction(t *testing.T) {
    // arrange, act, assert
}
```

Table-driven tests with subtests are the preferred pattern:

```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"valid input", "foo", "bar"},
        {"empty input", "", ""},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            result := MyFunction(tt.input)
            if result != tt.expected {
                t.Errorf("got %q, want %q", result, tt.expected)
            }
        })
    }
}
```

## Writing Acceptance Tests

Acceptance tests use the `terraform-plugin-testing` framework with `resource.TestCase`:

```go
func TestAccMyResource_basic(t *testing.T) {
    rName := acctest.RandomWithPrefix("tf-acc-test")
    resourceName := "jamfprotect_my_resource.test"

    resource.Test(t, resource.TestCase{
        PreCheck:                 func() { testutil.TestAccPreCheck(t) },
        ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
        CheckDestroy:             testAccCheckMyResourceDestroy,
        Steps: []resource.TestStep{
            {
                Config: testAccMyResourceConfig(rName),
                Check: resource.ComposeAggregateTestCheckFunc(
                    resource.TestCheckResourceAttrSet(resourceName, "id"),
                    resource.TestCheckResourceAttr(resourceName, "name", rName),
                ),
            },
            {
                ResourceName:      resourceName,
                ImportState:       true,
                ImportStateVerify: true,
            },
        },
    })
}
```

**Requirements:**

- Call `testutil.TestAccPreCheck(t)` in the `PreCheck` function.
- Always provide a `CheckDestroy` function that verifies resources are removed after the test.
- Use `acctest.RandomWithPrefix("tf-acc-")` for resource names to avoid conflicts.

## CI/CD

All CI jobs run in a single workflow: `.github/workflows/integration-tests.yml`, triggered on PRs to `main` and `workflow_dispatch`.

### Integration Jobs

| Job        | What it does                         | Timeout |
| ---------- | ------------------------------------ | ------- |
| `build`    | `go build` + `golangci-lint run`     | 5 min   |
| `generate` | Validates generated docs are current | --      |
| `unit`     | `go test -v -cover -count=1 ./...`   | 10 min  |

### Acceptance Tests (approval-gated)

Runs automatically after unit tests pass. Requires approval through the GitHub `acceptance` environment. Uses Terraform 1.14.x with credentials from repository secrets.

### Required GitHub Secrets

| Secret                      | Description                                                                  |
| --------------------------- | ---------------------------------------------------------------------------- |
| `JAMFPROTECT_URL`           | Jamf Protect tenant URL (e.g., `https://your-tenant.protect.jamfcloud.com`)  |
| `JAMFPROTECT_CLIENT_ID`     | API client ID                                                                |
| `JAMFPROTECT_CLIENT_SECRET` | API client secret                                                            |
