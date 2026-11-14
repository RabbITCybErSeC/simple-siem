package detectiontest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection/detectiontest"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

const manifestYAML = `id: brute-force-then-success
version: 1.0.0
name: Brute force followed by a successful login
owner: secops
severity: HIGH
inputs:
  - dataset: auth_events
    eventTypes: [USER_LOGIN]
window:
  size: 15m
  every: 5m
budgets:
  timeout: 30s
  maxRows: 1000000
  maxProposals: 100
  maxEvidencePerProposal: 1000
alerting:
  mode: MERGE
  identitySchemaVersion: 1
  identityFields:
    - path: target.user.userid
      required: true
    - path: target.hostname
  coalesceWindow: 2h
  maxAlertSpan: 24h
`

const fixtureJSON = `{
  "window": {"start": "2026-05-11T10:00:00Z", "end": "2026-05-11T10:15:00Z"},
  "datasets": {
    "auth_events": [
      {
        "sourceKey": {"fetcherInstanceId": "fixture", "index": "auth", "documentId": "1"},
        "event": {
          "metadata": {"event_timestamp": "2026-05-11T10:01:00Z", "event_type": "USER_LOGIN"},
          "target": {"user": {"userid": "alice"}, "hostname": "web01"},
          "security_result": {"action": "BLOCK"}
        }
      }
    ]
  },
  "expect": {
    "proposals": [
      {"identity": {"target.user.userid": "alice"}, "severity": "HIGH", "evidenceCount": 1}
    ]
  }
}`

type stubDetection func(ctx context.Context, window detection.Window) ([]detection.Proposal, error)

func (stub stubDetection) Evaluate(ctx context.Context, window detection.Window) ([]detection.Proposal, error) {
	return stub(ctx, window)
}

func TestRunFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "positive.json")
	if err := os.WriteFile(path, []byte(fixtureJSON), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	registration := detection.Registration{
		Manifest: []byte(manifestYAML),
		Logic: stubDetection(func(ctx context.Context, window detection.Window) ([]detection.Proposal, error) {
			var evidence []detection.Evidence
			for record, err := range window.Events(ctx, "auth_events") {
				if err != nil {
					return nil, err
				}
				evidence = append(evidence, detection.EvidenceOf(record))
			}
			return []detection.Proposal{{
				Subject: udm.Event{Target: udm.Noun{
					User:     udm.User{UserID: "alice"},
					Hostname: "web01",
				}},
				Summary:  "failed logon",
				Evidence: evidence,
			}}, nil
		}),
	}

	detectiontest.RunFixture(t, registration, path)
}
