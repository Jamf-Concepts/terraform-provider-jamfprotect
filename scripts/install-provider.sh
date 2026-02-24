#!/bin/bash
set -e

VERSION="${1:-0.1.0}"
GITHUB_ORG="Jamf-Concepts"
PROVIDER_NAME="jamfprotect"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Installing terraform-provider-${PROVIDER_NAME} v${VERSION}...${NC}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
x86_64) ARCH="amd64" ;;
aarch64 | arm64) ARCH="arm64" ;;
*)
	echo -e "${RED}Unsupported architecture: $ARCH${NC}"
	exit 1
	;;
esac

echo "Platform: ${OS}_${ARCH}"

# Plugin directory
PLUGIN_DIR="${HOME}/.terraform.d/plugins/github.com/${GITHUB_ORG}/${PROVIDER_NAME}/${VERSION}/${OS}_${ARCH}"
echo "Plugin directory: ${PLUGIN_DIR}"

# Create directory
mkdir -p "${PLUGIN_DIR}"

# Download URL
DOWNLOAD_URL="https://github.com/${GITHUB_ORG}/terraform-provider-${PROVIDER_NAME}/releases/download/v${VERSION}/terraform-provider-${PROVIDER_NAME}_${VERSION}_${OS}_${ARCH}.zip"

echo "Downloading from: ${DOWNLOAD_URL}"

# Download
TMP_FILE="/tmp/terraform-provider-${PROVIDER_NAME}-${VERSION}.zip"
if [ -n "$GITHUB_TOKEN" ]; then
	echo -e "${YELLOW}Using GITHUB_TOKEN for authentication${NC}"
	if ! curl -f -L -H "Authorization: token ${GITHUB_TOKEN}" "${DOWNLOAD_URL}" -o "${TMP_FILE}"; then
		echo -e "${RED}Failed to download provider. Check your GITHUB_TOKEN and repository access.${NC}"
		exit 1
	fi
else
	echo -e "${YELLOW}Downloading without authentication (repository must be public)${NC}"
	if ! curl -f -L "${DOWNLOAD_URL}" -o "${TMP_FILE}"; then
		echo -e "${RED}Failed to download provider. If the repository is private, set GITHUB_TOKEN environment variable.${NC}"
		echo -e "${YELLOW}Example: export GITHUB_TOKEN='your-github-personal-access-token'${NC}"
		exit 1
	fi
fi

# Extract
echo "Extracting to ${PLUGIN_DIR}..."
if ! unzip -o "${TMP_FILE}" -d "${PLUGIN_DIR}"; then
	echo -e "${RED}Failed to extract provider archive${NC}"
	rm -f "${TMP_FILE}"
	exit 1
fi

# Clean up
rm -f "${TMP_FILE}"

# Make executable
chmod +x "${PLUGIN_DIR}/"terraform-provider-*

# Verify
if [ -f "${PLUGIN_DIR}/terraform-provider-${PROVIDER_NAME}_v${VERSION}" ]; then
	echo -e "${GREEN}✅ Successfully installed terraform-provider-${PROVIDER_NAME} v${VERSION}${NC}"
	echo ""
	echo "Usage in your Terraform configuration:"
	echo ""
	echo "terraform {"
	echo "  required_providers {"
	echo "    ${PROVIDER_NAME} = {"
	echo "      source  = \"github.com/${GITHUB_ORG}/${PROVIDER_NAME}\""
	echo "      version = \"${VERSION}\""
	echo "    }"
	echo "  }"
	echo "}"
	echo ""
	echo "Run 'terraform init' to verify installation."
else
	echo -e "${RED}Installation completed but provider binary not found${NC}"
	exit 1
fi
