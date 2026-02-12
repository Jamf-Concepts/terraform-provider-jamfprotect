// SPDX-License-Identifier: MPL-2.0

// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func testAccProbeEnumValues(t *testing.T) (map[string][]string, error) {
	t.Helper()

	required := []string{"JAMFPROTECT_URL", "JAMFPROTECT_CLIENT_ID", "JAMFPROTECT_CLIENT_SECRET"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			return nil, fmt.Errorf("environment variable %s must be set", env)
		}
	}

	root, err := repoRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repo root: %w", err)
	}
	cmd := exec.Command("fnox", "exec", "--", "uv", "run", "tools/scripts/probe_app_types.py")
	cmd.Env = os.Environ()
	cmd.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("probe_app_types.py failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	var payload map[string][]struct {
		Message string `json:"message"`
		Info    string `json:"info"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse probe output: %w", err)
	}

	results := make(map[string][]string)
	re := regexp.MustCompile(`EnumValue\{name='([^']+)'\}`)
	for enumName, messages := range payload {
		for _, entry := range messages {
			matches := re.FindAllStringSubmatch(entry.Message, -1)
			for _, match := range matches {
				results[enumName] = append(results[enumName], match[1])
			}
		}
	}

	return results, nil
}

func repoRoot() (string, error) {
	start, err := os.Getwd()
	if err != nil {
		return "", err
	}
	current := start
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("go.mod not found from %s", start)
		}
		current = parent
	}
}
