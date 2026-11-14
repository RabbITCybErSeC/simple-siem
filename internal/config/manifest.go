package config

import (
	"errors"
	"fmt"
	"time"
)

// ParseDetectionManifest parses and validates one detection.yaml.
func ParseDetectionManifest(data []byte) (DetectionManifest, error) {
	var manifest DetectionManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return DetectionManifest{}, fmt.Errorf("detection manifest: %w", err)
	}

	if manifest.InitialStatus == "" {
		manifest.InitialStatus = "SHADOW"
	}
	if manifest.Alerting.Mode == "" {
		manifest.Alerting.Mode = "MERGE"
	}
	for index := range manifest.Inputs {
		if manifest.Inputs[index].OnStalledInput == "" {
			manifest.Inputs[index].OnStalledInput = "wait"
		}
	}

	var problems []error
	add := func(path string, message string) {
		problems = append(problems, fileError("detection manifest", path, message))
	}

	if !identifierPattern.MatchString(manifest.ID) {
		add("id", "invalid detection id")
	}
	if !versionPattern.MatchString(manifest.Version) {
		add("version", "must be MAJOR.MINOR.PATCH")
	}
	if manifest.Name == "" {
		add("name", "is required")
	}
	switch manifest.Severity {
	case "LOW", "MEDIUM", "HIGH":
	default:
		add("severity", "must be LOW, MEDIUM or HIGH")
	}
	switch manifest.InitialStatus {
	case "ENABLED", "SHADOW", "DISABLED":
	default:
		add("initialStatus", "must be ENABLED, SHADOW or DISABLED")
	}

	if len(manifest.Inputs) == 0 {
		add("inputs", "at least one input is required")
	}
	datasets := make(map[string]bool, len(manifest.Inputs))
	for index, input := range manifest.Inputs {
		prefix := fmt.Sprintf("inputs[%d].", index)
		if !datasetPattern.MatchString(input.Dataset) {
			add(prefix+"dataset", "invalid dataset name")
		}
		if datasets[input.Dataset] {
			add(prefix+"dataset", fmt.Sprintf("duplicate input dataset %q", input.Dataset))
		}
		datasets[input.Dataset] = true

		if len(input.EventTypes) == 0 {
			add(prefix+"eventTypes", "at least one event type is required")
		}
		for eventIndex, eventType := range input.EventTypes {
			if eventType == "" {
				add(fmt.Sprintf("%seventTypes[%d]", prefix, eventIndex), "must not be empty")
			}
		}
		switch input.OnStalledInput {
		case "wait", "fail":
		case "run_partial":
			add(prefix+"onStalledInput", "run_partial is available in Phase 3")
		default:
			add(prefix+"onStalledInput", "must be wait or fail")
		}
	}

	if manifest.Window.Size <= 0 {
		add("window.size", "must be positive")
	}
	if manifest.Window.Every <= 0 {
		add("window.every", "must be positive")
	}

	if manifest.Budgets.Timeout <= 0 {
		add("budgets.timeout", "must be positive")
	}
	if manifest.Budgets.MaxRows <= 0 {
		add("budgets.maxRows", "must be positive")
	}
	if manifest.Budgets.MaxProposals <= 0 {
		add("budgets.maxProposals", "must be positive")
	}
	if manifest.Budgets.MaxEvidencePerProposal <= 0 {
		add("budgets.maxEvidencePerProposal", "must be positive")
	}

	switch manifest.Alerting.Mode {
	case "MERGE", "UNIQUE", "ALWAYS_NEW":
	default:
		add("alerting.mode", "must be MERGE, UNIQUE or ALWAYS_NEW")
	}
	if manifest.Alerting.IdentitySchemaVersion < 1 {
		add("alerting.identitySchemaVersion", "must be at least 1")
	}

	if len(manifest.Alerting.IdentityFields) == 0 {
		add("alerting.identityFields", "at least one identity field is required")
	}
	identityPaths := make(map[string]bool, len(manifest.Alerting.IdentityFields))
	hasRequiredIdentity := false
	for index, field := range manifest.Alerting.IdentityFields {
		prefix := fmt.Sprintf("alerting.identityFields[%d].", index)
		if field.Path == "" {
			add(prefix+"path", "must not be empty")
		} else if identityPaths[field.Path] {
			add(prefix+"path", fmt.Sprintf("duplicate identity path %q", field.Path))
		}
		identityPaths[field.Path] = true
		if field.Required {
			hasRequiredIdentity = true
		}
	}
	if len(manifest.Alerting.IdentityFields) > 0 && !hasRequiredIdentity {
		add("alerting.identityFields", "at least one identity field must be required")
	}

	if manifest.Alerting.Mode == "MERGE" && manifest.Alerting.CoalesceWindow <= 0 {
		add("alerting.coalesceWindow", "must be positive when alerting mode is MERGE")
	}
	if manifest.Alerting.MaxAlertSpan <= 0 {
		add("alerting.maxAlertSpan", "must be positive")
	} else if manifest.Alerting.MaxAlertSpan < manifest.Alerting.CoalesceWindow {
		add("alerting.maxAlertSpan", "must be at least coalesceWindow")
	}

	if err := errors.Join(problems...); err != nil {
		return DetectionManifest{}, err
	}
	return manifest, nil
}

// ValidateDetections checks detection manifests against the loaded pipelines.
func ValidateDetections(files Files, manifests []DetectionManifest) error {
	datasetRetention := make(map[string]Duration)
	for _, pipeline := range files.Pipelines {
		for dataset, output := range pipeline.Outputs {
			retention := Duration(0)
			if output.Retention != nil {
				retention = *output.Retention
			}
			datasetRetention[dataset] = retention
		}
	}

	var problems []error
	seenIDs := make(map[string]bool, len(manifests))
	for _, manifest := range manifests {
		if seenIDs[manifest.ID] {
			problems = append(problems, fmt.Errorf("detection %q: duplicate detection id", manifest.ID))
		} else {
			seenIDs[manifest.ID] = true
		}

		for _, input := range manifest.Inputs {
			retention, exists := datasetRetention[input.Dataset]
			if !exists {
				problems = append(problems, fmt.Errorf("detection %q: input dataset %q is not written by a pipeline",
					manifest.ID, input.Dataset))
				continue
			}
			if manifest.Window.Size > retention {
				problems = append(problems, fmt.Errorf("detection %q: window.size %s exceeds input dataset %q retention %s",
					manifest.ID, time.Duration(manifest.Window.Size), input.Dataset, time.Duration(retention)))
			}
		}
	}
	return errors.Join(problems...)
}
