package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseDetectionManifest(t *testing.T) {
	data, err := os.ReadFile("testdata/manifests/valid.yaml")
	if err != nil {
		t.Fatalf("read valid manifest: %v", err)
	}
	manifestYAML := string(data)

	want := DetectionManifest{
		ID:            "brute-force-then-success",
		Version:       "1.0.0",
		Name:          "Brute force followed by a successful login",
		Owner:         "secops",
		Severity:      "HIGH",
		Tags:          []string{"attack.t1110"},
		InitialStatus: "SHADOW",
		Inputs: []DetectionInput{{
			Dataset:        "auth_events",
			EventTypes:     []string{"USER_LOGIN"},
			OnStalledInput: "wait",
		}},
		Window: DetectionWindow{
			Size:  Duration(15 * time.Minute),
			Every: Duration(5 * time.Minute),
		},
		Budgets: DetectionBudgets{
			Timeout:                Duration(30 * time.Second),
			MaxRows:                1000000,
			MaxProposals:           100,
			MaxEvidencePerProposal: 1000,
		},
		Alerting: DetectionAlerting{
			Mode:                  "MERGE",
			IdentitySchemaVersion: 1,
			IdentityFields: []IdentityField{
				{Path: "target.user.userid", Required: true},
				{Path: "target.hostname", Fallback: "target.ip"},
			},
			CoalesceWindow: Duration(2 * time.Hour),
			MaxAlertSpan:   Duration(24 * time.Hour),
		},
	}

	tests := []struct {
		name         string
		replacements [][2]string
		want         *DetectionManifest
		wantErrors   []string
	}{
		{
			name: "detection contract example",
			want: &want,
		},
		{
			name: "defaults applied",
			replacements: [][2]string{
				{"initialStatus: SHADOW\n", ""},
				{"    onStalledInput: wait\n", ""},
				{"  mode: MERGE\n", ""},
			},
			want: &want,
		},
		{
			name:         "unknown key",
			replacements: [][2]string{{"id: brute-force-then-success\n", "id: brute-force-then-success\nunknownKey: true\n"}},
			wantErrors:   []string{"unknown field", "unknownKey"},
		},
		{
			name:         "duplicate key",
			replacements: [][2]string{{"id: brute-force-then-success\n", "id: brute-force-then-success\nid: other\n"}},
			wantErrors:   []string{`"id"`, "already defined"},
		},
		{
			name:         "wrong type",
			replacements: [][2]string{{"size: 15m", "size: [15m]"}},
			wantErrors:   []string{"duration must be a string"},
		},
		{
			name:         "invalid id",
			replacements: [][2]string{{"id: brute-force-then-success", "id: Brute_Force"}},
			wantErrors:   []string{"id", "invalid detection id"},
		},
		{
			name:         "invalid version",
			replacements: [][2]string{{"version: 1.0.0", `version: "1.0"`}},
			wantErrors:   []string{"version", "MAJOR.MINOR.PATCH"},
		},
		{
			name:         "missing name",
			replacements: [][2]string{{"name: Brute force followed by a successful login\n", ""}},
			wantErrors:   []string{"name", "required"},
		},
		{
			name:         "invalid severity",
			replacements: [][2]string{{"severity: HIGH", "severity: CRITICAL"}},
			wantErrors:   []string{"severity", "LOW, MEDIUM or HIGH"},
		},
		{
			name:         "invalid initial status",
			replacements: [][2]string{{"initialStatus: SHADOW", "initialStatus: PAUSED"}},
			wantErrors:   []string{"initialStatus", "ENABLED, SHADOW or DISABLED"},
		},
		{
			name: "no inputs",
			replacements: [][2]string{{
				"inputs:\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n    onStalledInput: wait\n",
				"inputs: []\n",
			}},
			wantErrors: []string{"inputs", "at least one input"},
		},
		{
			name: "duplicate input dataset",
			replacements: [][2]string{{
				"    onStalledInput: wait\n",
				"    onStalledInput: wait\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n",
			}},
			wantErrors: []string{"inputs[1].dataset", "duplicate"},
		},
		{
			name:         "invalid dataset name",
			replacements: [][2]string{{"dataset: auth_events", "dataset: Auth-Events"}},
			wantErrors:   []string{"inputs[0].dataset", "invalid dataset name"},
		},
		{
			name:         "empty event types",
			replacements: [][2]string{{"eventTypes: [USER_LOGIN]", "eventTypes: []"}},
			wantErrors:   []string{"inputs[0].eventTypes", "at least one event type"},
		},
		{
			name:         "empty event type",
			replacements: [][2]string{{"eventTypes: [USER_LOGIN]", `eventTypes: [""]`}},
			wantErrors:   []string{"inputs[0].eventTypes[0]", "must not be empty"},
		},
		{
			name:         "run partial stalled input policy",
			replacements: [][2]string{{"onStalledInput: wait", "onStalledInput: run_partial"}},
			wantErrors:   []string{"available in Phase 3"},
		},
		{
			name:         "invalid stalled input policy",
			replacements: [][2]string{{"onStalledInput: wait", "onStalledInput: skip"}},
			wantErrors:   []string{"onStalledInput", "wait or fail"},
		},
		{
			name:         "zero window size",
			replacements: [][2]string{{"size: 15m", "size: 0s"}},
			wantErrors:   []string{"window.size", "must be positive"},
		},
		{
			name:         "zero window every",
			replacements: [][2]string{{"every: 5m", "every: 0s"}},
			wantErrors:   []string{"window.every", "must be positive"},
		},
		{
			name:         "zero budget timeout",
			replacements: [][2]string{{"timeout: 30s", "timeout: 0s"}},
			wantErrors:   []string{"budgets.timeout", "must be positive"},
		},
		{
			name:         "zero max rows",
			replacements: [][2]string{{"maxRows: 1000000", "maxRows: 0"}},
			wantErrors:   []string{"budgets.maxRows", "must be positive"},
		},
		{
			name:         "zero max proposals",
			replacements: [][2]string{{"maxProposals: 100", "maxProposals: 0"}},
			wantErrors:   []string{"budgets.maxProposals", "must be positive"},
		},
		{
			name:         "zero max evidence per proposal",
			replacements: [][2]string{{"maxEvidencePerProposal: 1000", "maxEvidencePerProposal: 0"}},
			wantErrors:   []string{"budgets.maxEvidencePerProposal", "must be positive"},
		},
		{
			name:         "invalid alerting mode",
			replacements: [][2]string{{"mode: MERGE", "mode: MERGE_ALL"}},
			wantErrors:   []string{"alerting.mode", "MERGE, UNIQUE or ALWAYS_NEW"},
		},
		{
			name:         "zero identity schema version",
			replacements: [][2]string{{"identitySchemaVersion: 1", "identitySchemaVersion: 0"}},
			wantErrors:   []string{"alerting.identitySchemaVersion", "at least 1"},
		},
		{
			name: "no identity fields",
			replacements: [][2]string{{
				"  identityFields:\n    - path: target.user.userid\n      required: true\n    - path: target.hostname\n      fallback: target.ip\n",
				"  identityFields: []\n",
			}},
			wantErrors: []string{"alerting.identityFields", "at least one identity field"},
		},
		{
			name:         "no required identity field",
			replacements: [][2]string{{"      required: true", "      required: false"}},
			wantErrors:   []string{"alerting.identityFields", "required"},
		},
		{
			name:         "empty identity path",
			replacements: [][2]string{{"path: target.hostname", `path: ""`}},
			wantErrors:   []string{"alerting.identityFields[1].path", "must not be empty"},
		},
		{
			name:         "duplicate identity path",
			replacements: [][2]string{{"path: target.hostname", "path: target.user.userid"}},
			wantErrors:   []string{"alerting.identityFields[1].path", "duplicate identity path"},
		},
		{
			name:         "zero coalesce window for merge",
			replacements: [][2]string{{"coalesceWindow: 2h", "coalesceWindow: 0s"}},
			wantErrors:   []string{"alerting.coalesceWindow", "MERGE"},
		},
		{
			name:         "zero max alert span",
			replacements: [][2]string{{"maxAlertSpan: 24h", "maxAlertSpan: 0s"}},
			wantErrors:   []string{"alerting.maxAlertSpan", "must be positive"},
		},
		{
			name:         "max alert span below the coalesce window",
			replacements: [][2]string{{"maxAlertSpan: 24h", "maxAlertSpan: 1h"}},
			wantErrors:   []string{"alerting.maxAlertSpan", "at least coalesceWindow"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := manifestYAML
			for _, replacement := range test.replacements {
				if !strings.Contains(input, replacement[0]) {
					t.Fatalf("manifest fixture does not contain %q", replacement[0])
				}
				input = strings.ReplaceAll(input, replacement[0], replacement[1])
			}

			manifest, err := ParseDetectionManifest([]byte(input))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("ParseDetectionManifest() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(manifest, DetectionManifest{}) {
					t.Fatalf("ParseDetectionManifest() = %+v, want the zero manifest when validation fails", manifest)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDetectionManifest() error = %v, want nil", err)
			}
			if !strings.Contains(manifest.Description, "Many failed logons for one account on one host, then a success from the same origin inside the window.") {
				t.Errorf("Description = %q, want the manifest description", manifest.Description)
			}

			got, expected := manifest, *test.want
			got.Description, expected.Description = "", ""
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("ParseDetectionManifest() = %+v, want %+v", got, expected)
			}
		})
	}
}

func TestValidateDetections(t *testing.T) {
	durationPointer := func(value time.Duration) *Duration {
		duration := Duration(value)
		return &duration
	}
	files := Files{Pipelines: []Pipeline{{
		ID: "auth-events",
		Outputs: map[string]Output{
			"auth_events": {From: "udm.auth_events", Retention: durationPointer(72 * time.Hour)},
		},
	}}}

	manifest := func(id string, dataset string, size time.Duration) DetectionManifest {
		return DetectionManifest{
			ID:     id,
			Inputs: []DetectionInput{{Dataset: dataset}},
			Window: DetectionWindow{Size: Duration(size)},
		}
	}

	tests := []struct {
		name       string
		files      Files
		manifests  []DetectionManifest
		wantErrors []string
	}{
		{
			name:      "valid manifests",
			files:     files,
			manifests: []DetectionManifest{manifest("brute-force-then-success", "auth_events", 15*time.Minute)},
		},
		{
			name:  "duplicate manifest ids",
			files: files,
			manifests: []DetectionManifest{
				manifest("brute-force-then-success", "auth_events", 15*time.Minute),
				manifest("brute-force-then-success", "auth_events", 15*time.Minute),
			},
			wantErrors: []string{"brute-force-then-success", "duplicate detection id"},
		},
		{
			name:       "unknown input dataset",
			files:      files,
			manifests:  []DetectionManifest{manifest("brute-force-then-success", "edr_events", 15*time.Minute)},
			wantErrors: []string{"brute-force-then-success", "edr_events", "not written by a pipeline"},
		},
		{
			name: "window larger than retention",
			files: Files{Pipelines: []Pipeline{{
				ID: "auth-events",
				Outputs: map[string]Output{
					"auth_events": {From: "udm.auth_events", Retention: durationPointer(time.Hour)},
				},
			}}},
			manifests:  []DetectionManifest{manifest("brute-force-then-success", "auth_events", 2*time.Hour)},
			wantErrors: []string{"brute-force-then-success", "window.size", "auth_events", "retention", "2h0m0s", "1h0m0s"},
		},
		{
			name:  "every problem is joined",
			files: files,
			manifests: []DetectionManifest{
				manifest("brute-force-then-success", "auth_events", 15*time.Minute),
				manifest("brute-force-then-success", "unknown_events", 15*time.Minute),
			},
			wantErrors: []string{"duplicate detection id", "unknown_events", "not written by a pipeline"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDetections(test.files, test.manifests)

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("ValidateDetections() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) == 0 && err != nil {
				t.Fatalf("ValidateDetections() error = %v, want nil", err)
			}
		})
	}
}
