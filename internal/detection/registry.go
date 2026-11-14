package detection

import (
	"errors"
	"fmt"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// Registry is the validated set of compiled detections. Manifests holds every
// compiled detection by id; Inactive holds the warning for detections whose
// input no loaded pipeline writes.
type Registry struct {
	Manifests map[string]config.DetectionManifest
	Inactive  map[string]string
}

// ValidateRegistrations parses and validates every compiled detection, then
// checks the active ones against the loaded pipelines. Catalog problems are
// hard errors whatever the configuration. A detection whose input dataset no
// pipeline writes is inactive instead: the product binary must not reject a
// config directory that omits an example detection's dataset.
func ValidateRegistrations(registrations []Registration, files config.Files) (Registry, error) {
	written := make(map[string]bool)
	for _, pipeline := range files.Pipelines {
		for datasetName := range pipeline.Outputs {
			written[datasetName] = true
		}
	}

	registry := Registry{
		Manifests: make(map[string]config.DetectionManifest, len(registrations)),
		Inactive:  make(map[string]string),
	}
	active := make([]config.DetectionManifest, 0, len(registrations))
	seen := make(map[string]bool, len(registrations))
	var problems []error

	for index, registration := range registrations {
		manifest, err := config.ParseDetectionManifest(registration.Manifest)
		if err != nil {
			problems = append(problems, fmt.Errorf("registration %d: %w", index, err))
			continue
		}
		if registration.Logic == nil {
			problems = append(problems, fmt.Errorf("detection %q: logic is nil", manifest.ID))
		}
		if seen[manifest.ID] {
			problems = append(problems, fmt.Errorf("detection %q: duplicate detection id", manifest.ID))
			continue
		}
		seen[manifest.ID] = true
		problems = append(problems, catalogProblems(manifest)...)
		registry.Manifests[manifest.ID] = manifest

		missingInput := ""
		for _, input := range manifest.Inputs {
			if !written[input.Dataset] {
				missingInput = input.Dataset
				break
			}
		}
		if missingInput != "" {
			registry.Inactive[manifest.ID] = fmt.Sprintf(
				"detection %s inactive: input dataset %s not configured", manifest.ID, missingInput)
			continue
		}
		active = append(active, manifest)
	}

	if err := config.ValidateDetections(files, active); err != nil {
		problems = append(problems, err)
	}
	if err := errors.Join(problems...); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

// catalogProblems checks the manifest against the UDM catalog and enum values.
// It runs for every detection, active or not.
func catalogProblems(manifest config.DetectionManifest) []error {
	var problems []error
	for inputIndex, input := range manifest.Inputs {
		for eventIndex, eventType := range input.EventTypes {
			if !udm.EventType(eventType).Valid() {
				problems = append(problems, fmt.Errorf(
					"detection %q: inputs[%d].eventTypes[%d]: invalid UDM event type %q",
					manifest.ID, inputIndex, eventIndex, eventType))
			}
		}
	}
	for fieldIndex, field := range manifest.Alerting.IdentityFields {
		if _, ok := udm.Lookup(field.Path); !ok {
			problems = append(problems, fmt.Errorf(
				"detection %q: alerting.identityFields[%d].path %q is not in the UDM catalog",
				manifest.ID, fieldIndex, field.Path))
		}
		if field.Fallback != "" {
			if _, ok := udm.Lookup(field.Fallback); !ok {
				problems = append(problems, fmt.Errorf(
					"detection %q: alerting.identityFields[%d].fallback %q is not in the UDM catalog",
					manifest.ID, fieldIndex, field.Fallback))
			}
		}
	}
	return problems
}
