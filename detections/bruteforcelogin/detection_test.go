package bruteforcelogin

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
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

func TestFailureBufferIsBounded(t *testing.T) {
	var current attempts
	const failures = 50000

	for index := 0; index < failures; index++ {
		current.recordFailure(dataset.Record{Key: dataset.SourceKey{DocumentID: strconv.Itoa(index)}})
		if buffered := current.bufferedFailures(); buffered > maxBufferedFailures {
			t.Fatalf("buffered failures after %d = %d, want at most %d", index+1, buffered, maxBufferedFailures)
		}
	}
	if buffered := current.bufferedFailures(); buffered != maxBufferedFailures {
		t.Fatalf("buffered failures = %d, want the latest %d", buffered, maxBufferedFailures)
	}
	if current.failureCount != failures {
		t.Fatalf("failure count = %d, want the real total %d", current.failureCount, failures)
	}

	success := dataset.Record{Key: dataset.SourceKey{DocumentID: "success"}}
	evidence := current.evidenceOf(success)
	if len(evidence) != maxBufferedFailures+1 {
		t.Fatalf("evidence = %d, want %d records", len(evidence), maxBufferedFailures+1)
	}
	for offset := 0; offset < maxBufferedFailures; offset++ {
		want := strconv.Itoa(failures - maxBufferedFailures + offset)
		if got := evidence[offset].SourceKey.DocumentID; got != want {
			t.Fatalf("evidence %d document = %q, want %q (oldest first)", offset, got, want)
		}
	}
	if got := evidence[maxBufferedFailures].SourceKey.DocumentID; got != "success" {
		t.Fatalf("last evidence document = %q, want the success", got)
	}
}
