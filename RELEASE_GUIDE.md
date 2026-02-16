# 🚀 Publishing v0.1.0 to Terraform Registry - Complete Guide

## 📋 Pre-Release Checklist

Before creating the v0.1.0 release, ensure the following are complete:

### ✅ **Code Quality**

- [x] All unit tests pass: `mise run test`
- [x] All acceptance tests pass: `mise run testacc` (requires credentials)
- [x] Code is formatted: `mise run fmt`
- [x] Documentation is up to date: `mise run build:generate-docs`
- [x] PII has been removed from git history
- [x] Repository is clean: `git status`

### ✅ **Documentation**

- [x] README.md updated with all 9 resources and 9 data sources
- [x] CHANGELOG.md includes all features for v0.1.0
- [x] AGENTS.md reflects current project structure
- [x] All example files present in `examples/`
- [x] All generated docs present in `docs/`

### ✅ **Repository Status**

- [x] All changes committed
- [x] Local main branch is up to date
- [x] Remote repository is in sync: `git push origin main`

______________________________________________________________________

## 🔐 Prerequisites (One-Time Setup)

These steps only need to be done once before your first release:

### **1. Terraform Registry Account Setup**

1. Go to [registry.terraform.io](https://registry.terraform.io)
2. Sign in with your GitHub account (`smithjw`)
3. Verify you have access to publish under the `smithjw` namespace
4. Go to [Settings > General](https://registry.terraform.io/settings) and ensure your account is active

### **2. GPG Signing Key Setup**

The Terraform Registry requires GPG-signed releases. You need to:

**a. Check if you already have a GPG key:**

```bash
gpg --list-secret-keys --keyid-format=long
```

**b. If you don't have one, generate a new GPG key:**

```bash
# Generate key (use your GitHub email)
gpg --full-generate-key

# Choose:
# - Key type: (1) RSA and RSA
# - Key size: 4096
# - Expiration: 0 (does not expire) or set expiration
# - Real name: James Smith
# - Email: james@smithjw.me (must match GitHub email)
```

**c. Get your GPG key ID:**

```bash
gpg --list-secret-keys --keyid-format=long

# Output will look like:
# sec   rsa4096/ABCD1234EFGH5678 2024-01-01 [SC]
#                   ^^^^^^^^^^^^ This is your key ID
```

**d. Export your public key:**

```bash
# Replace ABCD1234EFGH5678 with your actual key ID
gpg --armor --export ABCD1234EFGH5678
```

**e. Add public key to Terraform Registry:**

1. Go to [registry.terraform.io/settings/gpg-keys](https://registry.terraform.io/settings/gpg-keys)
2. Click "Add GPG Key"
3. Paste the entire GPG public key (including `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----`)
4. Click "Add key"

### **3. GitHub Secrets Setup**

Add your GPG private key and passphrase to GitHub repository secrets:

**a. Export your GPG private key:**

```bash
# Replace ABCD1234EFGH5678 with your actual key ID
gpg --armor --export-secret-keys ABCD1234EFGH5678
```

**b. Add secrets to GitHub:**

1. Go to your repository: https://github.com/smithjw/terraform-provider-jamfprotect
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret** and add:
   - **Name:** `GPG_PRIVATE_KEY`
   - **Value:** (paste the entire private key output from above)
4. Click **Add secret**
5. Click **New repository secret** again and add:
   - **Name:** `PASSPHRASE`
   - **Value:** (your GPG key passphrase)
6. Click **Add secret**

### **4. Repository Permissions**

Ensure GitHub Actions has write permissions:

1. Go to **Settings** → **Actions** → **General**
2. Scroll to **Workflow permissions**
3. Select **Read and write permissions**
4. Check **Allow GitHub Actions to create and approve pull requests**
5. Click **Save**

______________________________________________________________________

## 🎯 Release Process for v0.1.0

Once the prerequisites are complete, follow these steps to publish v0.1.0:

### **Step 1: Verify Everything is Ready**

```bash
# Ensure you're on the main branch
git checkout main

# Pull latest changes (should already be up to date)
git pull origin main

# Verify tests pass
mise run test

# Verify no uncommitted changes
git status

# Check current commit
git log --oneline -1
```

Expected output:

```
7de20b3 Update documentation for v0.1.0 release
```

### **Step 2: Update CHANGELOG**

Update the CHANGELOG to mark v0.1.0 as released with today's date:

```bash
# Edit CHANGELOG.md manually or use sed
sed -i '' 's/## 0.1.0 (Unreleased)/## 0.1.0 (February 13, 2026)/' CHANGELOG.md

# Commit the change
git add CHANGELOG.md
git commit --no-gpg-sign --author="opencode <noreply@opencode.ai>" -m "Release v0.1.0"

# Push to remote
git push origin main
```

### **Step 3: Create and Push the v0.1.0 Tag**

```bash
# Create the tag (must start with 'v')
git tag v0.1.0

# Push the tag to GitHub
git push origin v0.1.0
```

**IMPORTANT:** The tag **must** start with `v` (e.g., `v0.1.0`, not `0.1.0`) because the GitHub Actions workflow is configured to trigger on `v*` tags.

### **Step 4: Monitor the Release Workflow**

1. Go to your repository's Actions tab: https://github.com/smithjw/terraform-provider-jamfprotect/actions
2. You should see a new workflow run named "Release" triggered by the `v0.1.0` tag
3. Click on the workflow run to monitor progress

The workflow will:

- ✅ Check out the code
- ✅ Set up Go using `mise`
- ✅ Import your GPG key from secrets
- ✅ Build binaries for all platforms (darwin, linux, windows, freebsd × amd64, arm64, etc.)
- ✅ Generate SHA256 checksums
- ✅ Sign checksums with GPG
- ✅ Create a GitHub release with all artifacts
- ✅ Upload the Terraform registry manifest

The workflow typically takes **3-5 minutes** to complete.

### **Step 5: Verify the GitHub Release**

Once the workflow completes:

1. Go to https://github.com/smithjw/terraform-provider-jamfprotect/releases
2. You should see a new release: **v0.1.0**
3. Verify it contains:
   - ✅ Release notes (from CHANGELOG)
   - ✅ Binary archives (`.zip` files for each platform)
   - ✅ `terraform-provider-jamfprotect_0.1.0_SHA256SUMS` (checksum file)
   - ✅ `terraform-provider-jamfprotect_0.1.0_SHA256SUMS.sig` (GPG signature)
   - ✅ `terraform-provider-jamfprotect_0.1.0_manifest.json` (Terraform registry manifest)

### **Step 6: Verify Terraform Registry Publication**

The Terraform Registry automatically detects new releases from GitHub. This can take **5-15 minutes**.

1. Go to https://registry.terraform.io/providers/smithjw/jamfprotect
2. Wait for the provider to appear (first time) or the new version to be listed
3. Verify the version **0.1.0** is available
4. Click on the version to see the documentation

______________________________________________________________________

## 📦 Using the Published Provider

Once published, users (including you) can use the provider like this:

```hcl
terraform {
  required_providers {
    jamfprotect = {
      source  = "smithjw/jamfprotect"
      version = "0.1.0"
    }
  }
}

provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = var.jamfprotect_client_id
  client_secret = var.jamfprotect_client_secret
}
```

Then run:

```bash
terraform init
```

Terraform will automatically download the provider from the registry.

______________________________________________________________________

## 🐛 Troubleshooting

### **Workflow fails with "GPG signing error"**

- Verify `GPG_PRIVATE_KEY` and `PASSPHRASE` secrets are correctly set in GitHub
- Ensure the private key includes the complete key block
- Check that the GPG key is not expired: `gpg --list-keys`

### **Provider doesn't appear on Terraform Registry**

- Verify the release includes `terraform-provider-jamfprotect_0.1.0_manifest.json`
- Check that the GPG signature is valid
- The Terraform Registry can take up to 15 minutes to detect new releases
- Ensure your public GPG key is registered in the Terraform Registry

### **"Checksum mismatch" when using the provider**

- This usually means the release artifacts were corrupted or modified
- Delete the release and tag, fix any issues, and re-release with a new tag

### **Tag already exists error**

```bash
# If you need to delete a tag and recreate it
git tag -d v0.1.0                    # Delete local tag
git push origin --delete v0.1.0      # Delete remote tag
# Then recreate and push again
```

______________________________________________________________________

## 🔄 Future Releases (v0.1.1, v0.2.0, etc.)

For future releases, the process is simpler:

1. Make your code changes
2. Update `CHANGELOG.md` with new version
3. Commit changes and push to `main`
4. Create and push a new tag: `git tag v0.1.1 && git push origin v0.1.1`
5. The release workflow runs automatically

______________________________________________________________________

## 📊 Current Repository Status

```
✅ Repository: terraform-provider-jamfprotect
✅ Resources: 9 (all with CRUD + import)
✅ Data Sources: 9 (all with pagination)
✅ Test Coverage: GraphQL Client 89.7%, Provider 4.3%
✅ Documentation: Complete (generated + examples)
✅ PII Status: All removed from history
✅ Branch: main (7de20b3)
✅ Ready for: v0.1.0 public release
```

______________________________________________________________________

## ✨ Next Steps After v0.1.0

Once v0.1.0 is published, you can:

1. **Announce the release** on social media, HashiCorp community forums, etc.
2. **Gather feedback** from early users
3. **Plan v0.2.0** with additional features or bug fixes
4. **Add a badge** to README.md showing the latest version from the registry
