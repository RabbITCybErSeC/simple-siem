package bruteforcelogin

import (
	"path/filepath"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection/detectiontest"
)

func TestFixtures(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatalf("find fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			detectiontest.RunFixture(t, Registration, path)
		})
	}
}

func TestEvidenceCapKeepsTheRealFailureCount(t *testing.T) {
	parsed, err := config.ParseDetectionManifest(manifest)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	path := filepath.Join("testdata", "edge_evidence_cap.json")

	result, err := detection.EvaluateFixture(Registration, parsed, path)
	if err != nil {
		t.Fatalf("EvaluateFixture() error = %v, want nil", err)
	}
	if !result.Passed {
		t.Fatalf("fixture differences = %v, want a pass", result.Differences)
	}
	if len(result.Proposals) != 1 {
		t.Fatalf("proposals = %d, want 1", len(result.Proposals))
	}
	if got := result.Proposals[0].Details["failed_attempts"]; got != "1200" {
		t.Fatalf("failed_attempts = %q, want the real count 1200", got)
	}
}
