// Package detectiontest runs detection fixtures from Go tests.
package detectiontest

import (
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
)

// RunFixture validates the registration's manifest, evaluates one fixture
// through the production checks, and fails the test with every difference.
func RunFixture(t *testing.T, registration detection.Registration, path string) {
	t.Helper()
	manifest, err := config.ParseDetectionManifest(registration.Manifest)
	if err != nil {
		t.Fatalf("fixture %s: manifest: %v", path, err)
	}
	result, err := detection.EvaluateFixture(registration, manifest, path)
	if err != nil {
		t.Fatalf("fixture %s: %v", path, err)
	}
	if !result.Passed {
		t.Fatalf("fixture %s failed:\n%s", path, strings.Join(result.Differences, "\n"))
	}
}
