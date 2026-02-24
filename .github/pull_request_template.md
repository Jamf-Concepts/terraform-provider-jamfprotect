# Pull Request

## Description

<!-- Provide a brief description of the changes in this PR -->

## Type of Change

<!-- Check all that apply -->

- [ ] New resource
- [ ] New data source
- [ ] Bug fix
- [ ] Enhancement to existing resource/data source
- [ ] Documentation update
- [ ] Refactoring/code cleanup
- [ ] CI/CD changes
- [ ] Other (please describe):

## Resources/Data Sources Modified

<!-- List the resources or data sources added or modified -->

- `jamfprotect_<resource_name>`
- `data.jamfprotect_<data_source_name>`

## Testing

### Integration Tests

- [ ] Added unit and acceptance tests for new resources/data sources in their respective `_test.go` files
- [ ] All integration tests pass locally (`go test -v ./testing/...`)

### Manual Testing

- [ ] Tested `terraform apply` against a test Jamf Protect instance
- [ ] Tested resource/data source CRUD operations (Create, Read, Update, Delete)
- [ ] Verified resources appear correctly in Jamf Protect UI

### Screenshots

<!-- Include screenshots showing the resources in the Jamf Protect UI -->

<details>
<summary>Resource in Jamf Protect UI</summary>

<!-- Paste screenshot(s) here -->

</details>

## Checklist

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings or errors
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing integration tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Additional Context

<!-- Add any other context about the PR here -->

## Related Issues

<!-- Link any related issues here using #issue_number -->

Fixes #
Relates to #

---

## For Reviewers

<!-- This section is for reviewers to use during PR review -->

### Review Checklist

- [ ] Code quality and style
- [ ] Test coverage is adequate
- [ ] Documentation is clear and complete
- [ ] Integration tests pass in CI
- [ ] Screenshots show expected behavior in Jamf Protect UI
- [ ] No breaking changes (or properly documented)
