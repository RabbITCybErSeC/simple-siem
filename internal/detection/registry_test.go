package detection

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
)

const testManifestYAML = `id: brute-force-then-success
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
      fallback: target.ip
  coalesceWindow: 2h
  maxAlertSpan: 24h
`

func manifestYAML(t *testing.T, replacements ...[2]string) []byte {
	t.Helper()
	data := testManifestYAML
	for _, replacement := range replacements {
		if !strings.Contains(data, replacement[0]) {
			t.Fatalf("manifest replacement %q does not match testManifestYAML", replacement[0])
		}
		data = strings.Replace(data, replacement[0], replacement[1], 1)
	}
	return []byte(data)
}

func parseManifest(t *testing.T, replacements ...[2]string) config.DetectionManifest {
	t.Helper()
	manifest, err := config.ParseDetectionManifest(manifestYAML(t, replacements...))
	if err != nil {
		t.Fatalf("parse test manifest: %v", err)
	}
	return manifest
}

type noopDetection struct{}

func (noopDetection) Evaluate(context.Context, Window) ([]Proposal, error) {
	return nil, nil
}

func registrationFor(t *testing.T, replacements ...[2]string) Registration {
	t.Helper()
	return Registration{Manifest: manifestYAML(t, replacements...), Logic: noopDetection{}}
}

func configFilesWriting(datasetNames ...string) config.Files {
	retention := config.Duration(72 * time.Hour)
	outputs := make(map[string]config.Output, len(datasetNames))
	for _, name := range datasetNames {
		outputs[name] = config.Output{From: "udm." + name, Retention: &retention}
	}
	return config.Files{Pipelines: []config.Pipeline{{ID: "auth-events", Outputs: outputs}}}
}

func configFilesWithRetention(datasetName string, retention time.Duration) config.Files {
	value := config.Duration(retention)
	return config.Files{Pipelines: []config.Pipeline{{
		ID:      "auth-events",
		Outputs: map[string]config.Output{datasetName: {From: "udm." + datasetName, Retention: &value}},
	}}}
}

func TestValidateRegistrations(t *testing.T) {
	twoInputs := [2]string{
		"inputs:\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n",
		"inputs:\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n  - dataset: edr_events\n    eventTypes: [USER_LOGIN]\n",
	}

	tests := []struct {
		name          string
		registrations []Registration
		files         config.Files
		wantErrors    []string
		wantManifests []string
		wantInactive  map[string]string
	}{
		{
			name:          "active detection",
			registrations: []Registration{registrationFor(t)},
			files:         configFilesWriting("auth_events"),
			wantManifests: []string{"brute-force-then-success"},
		},
		{
			name:          "dataset no pipeline writes makes the detection inactive",
			registrations: []Registration{registrationFor(t)},
			files:         config.Files{},
			wantManifests: []string{"brute-force-then-success"},
			wantInactive: map[string]string{
				"brute-force-then-success": "detection brute-force-then-success inactive: input dataset auth_events not configured",
			},
		},
		{
			name:          "first missing input in manifest order is named",
			registrations: []Registration{registrationFor(t, twoInputs)},
			files:         configFilesWriting("edr_events"),
			wantManifests: []string{"brute-force-then-success"},
			wantInactive: map[string]string{
				"brute-force-then-success": "detection brute-force-then-success inactive: input dataset auth_events not configured",
			},
		},
		{
			name:          "window larger than retention is an error for an active detection",
			registrations: []Registration{registrationFor(t)},
			files:         configFilesWithRetention("auth_events", 10*time.Minute),
			wantErrors:    []string{"brute-force-then-success", "window.size", "auth_events", "retention"},
		},
		{
			name:          "window larger than retention is fine for an inactive detection",
			registrations: []Registration{registrationFor(t)},
			files:         config.Files{},
			wantManifests: []string{"brute-force-then-success"},
			wantInactive: map[string]string{
				"brute-force-then-success": "detection brute-force-then-success inactive: input dataset auth_events not configured",
			},
		},
		{
			name: "unknown identity path",
			registrations: []Registration{registrationFor(t,
				[2]string{"path: target.user.userid", "path: target.user.email"},
			)},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"brute-force-then-success", "target.user.email", "UDM catalog"},
		},
		{
			name: "unknown identity fallback",
			registrations: []Registration{registrationFor(t,
				[2]string{"fallback: target.ip", "fallback: target.domain"},
			)},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"brute-force-then-success", "target.domain", "UDM catalog"},
		},
		{
			name: "invalid input event type",
			registrations: []Registration{registrationFor(t,
				[2]string{"eventTypes: [USER_LOGIN]", "eventTypes: [USER_LOGON]"},
			)},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"brute-force-then-success", "inputs[0].eventTypes[0]", "USER_LOGON"},
		},
		{
			name: "catalog errors stay hard for an inactive detection",
			registrations: []Registration{registrationFor(t,
				[2]string{"eventTypes: [USER_LOGIN]", "eventTypes: [USER_LOGON]"},
			)},
			files:      config.Files{},
			wantErrors: []string{"brute-force-then-success", "USER_LOGON"},
		},
		{
			name: "nil logic",
			registrations: []Registration{{
				Manifest: manifestYAML(t),
			}},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"brute-force-then-success", "logic"},
		},
		{
			name: "duplicate detection ids",
			registrations: []Registration{
				registrationFor(t),
				registrationFor(t),
			},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"brute-force-then-success", "duplicate detection id"},
		},
		{
			name: "manifest does not parse",
			registrations: []Registration{{
				Manifest: []byte("id: [\n"),
				Logic:    noopDetection{},
			}},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"detection manifest"},
		},
		{
			name: "every problem is joined",
			registrations: []Registration{
				registrationFor(t),
				registrationFor(t,
					[2]string{"path: target.user.userid", "path: target.user.email"},
				),
				registrationFor(t, [2]string{
					"id: brute-force-then-success",
					"id: suspicious-login",
				}, [2]string{
					"eventTypes: [USER_LOGIN]",
					"eventTypes: [USER_LOGON]",
				}, [2]string{
					"path: target.user.userid",
					"path: target.user.email",
				}),
			},
			files:      configFilesWriting("auth_events"),
			wantErrors: []string{"duplicate detection id", "target.user.email", "USER_LOGON"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := ValidateRegistrations(test.registrations, test.files)

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("ValidateRegistrations() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) > 0 {
				return
			}
			if err != nil {
				t.Fatalf("ValidateRegistrations() error = %v, want nil", err)
			}
			for _, id := range test.wantManifests {
				if _, exists := registry.Manifests[id]; !exists {
					t.Fatalf("Registry.Manifests has no %q; got %v", id, registry.Manifests)
				}
			}
			if len(registry.Inactive) != len(test.wantInactive) {
				t.Fatalf("Registry.Inactive = %v, want %v", registry.Inactive, test.wantInactive)
			}
			for id, warning := range test.wantInactive {
				if registry.Inactive[id] != warning {
					t.Fatalf("Registry.Inactive[%q] = %q, want %q", id, registry.Inactive[id], warning)
				}
			}
		})
	}
}

func TestValidateRegistrationsKeepsParsedManifest(t *testing.T) {
	want := parseManifest(t)

	registry, err := ValidateRegistrations([]Registration{{Manifest: manifestYAML(t), Logic: noopDetection{}}}, configFilesWriting("auth_events"))
	if err != nil {
		t.Fatalf("ValidateRegistrations() error = %v, want nil", err)
	}

	got, exists := registry.Manifests[want.ID]
	if !exists {
		t.Fatalf("Registry.Manifests has no %q", want.ID)
	}
	if got.Window.Size != want.Window.Size || got.Budgets.MaxRows != want.Budgets.MaxRows || got.Alerting.Mode != want.Alerting.Mode {
		t.Fatalf("Registry.Manifests[%q] = %+v, want the parsed manifest %+v", want.ID, got, want)
	}
}
