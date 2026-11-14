package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

const (
	maxSummaryBytes     = 500
	maxDetailEntries    = 50
	maxDetailValueBytes = 1024
	maxPanicStackBytes  = 4096
)

// LoadFixture decodes and validates one fixture file. Every event must pass
// UDM validation; a fixture with an invalid event is a broken test, not a test
// failure to compare.
func LoadFixture(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("fixture %s: %w", path, err)
	}

	var file fixtureFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return Fixture{}, fmt.Errorf("fixture %s: %w", path, err)
	}
	if !file.Window.Start.Before(file.Window.End) {
		return Fixture{}, fmt.Errorf("fixture %s: window.start must be before window.end", path)
	}

	fixture := Fixture{
		Window:   FixtureWindow{Start: file.Window.Start, End: file.Window.End},
		Datasets: make(map[string][]dataset.Record, len(file.Datasets)),
		Expect:   file.Expect,
	}
	for _, datasetName := range slices.Sorted(maps.Keys(file.Datasets)) {
		fileRecords := file.Datasets[datasetName]
		records := make([]dataset.Record, len(fileRecords))
		for index, fileRecord := range fileRecords {
			problems := udm.Validate(fileRecord.Event)
			if len(problems) > 0 {
				messages := make([]string, len(problems))
				for problemIndex, problem := range problems {
					messages[problemIndex] = problem.Error()
				}
				return Fixture{}, fmt.Errorf("fixture %s: dataset %s[%d]: %s",
					path, datasetName, index, strings.Join(messages, "; "))
			}
			records[index] = dataset.Record{
				Key:       fileRecord.SourceKey,
				EventTime: fileRecord.Event.Metadata.EventTimestamp,
				Event:     fileRecord.Event,
			}
		}
		fixture.Datasets[datasetName] = records
	}
	fixture.reader = newFixtureReader(fixture.Datasets)
	return fixture, nil
}

// EvaluateFixture runs one fixture through the same evaluation and proposal
// checks as a production window, then compares the result with its expectation.
func EvaluateFixture(registration Registration, manifest config.DetectionManifest, path string) (FixtureResult, error) {
	fixture, err := LoadFixture(path)
	if err != nil {
		return FixtureResult{}, err
	}

	inputs := declaredInputs(manifest)
	for _, name := range slices.Sorted(maps.Keys(fixture.Datasets)) {
		if _, declared := inputs[name]; !declared {
			return FixtureResult{}, fmt.Errorf("fixture %s: dataset %q is not a declared input", path, name)
		}
	}

	window := Window{
		Start:    fixture.Window.Start,
		End:      fixture.Window.End,
		Revision: 1,
		reader:   fixture.reader,
		inputs:   inputs,
		budget:   newRowBudget(manifest.Budgets.MaxRows),
	}
	outcome := evaluate(context.Background(), manifest, registration.Logic, window)
	if outcome.status != RunStatusOK {
		return FixtureResult{Differences: []string{fmt.Sprintf("run %s: %v", outcome.status, outcome.err)}}, nil
	}

	result := FixtureResult{Proposals: outcome.proposals}
	result.Differences = compareProposals(manifest, outcome.proposals, fixture.Expect.Proposals)
	result.Passed = len(result.Differences) == 0
	return result, nil
}

// evaluate runs the logic in its own goroutine with panic recovery and the
// manifest deadline, then checks the proposals. The runner and fixtures share
// it, so a fixture exercises exactly the production steps.
func evaluate(ctx context.Context, manifest config.DetectionManifest, logic Detection, window Window) evaluation {
	if logic == nil {
		return evaluation{status: RunStatusFailed, err: errors.New("detection logic is nil")}
	}

	timeout := time.Duration(manifest.Budgets.Timeout)
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		proposals  []Proposal
		err        error
		panicValue any
		stack      []byte
	}
	outcomes := make(chan outcome, 1)
	go func() {
		result := outcome{}
		defer func() {
			if value := recover(); value != nil {
				result.panicValue = value
				result.stack = debug.Stack()
			}
			outcomes <- result
		}()
		result.proposals, result.err = logic.Evaluate(runContext, window)
	}()

	var result outcome
	select {
	case result = <-outcomes:
	case <-runContext.Done():
		// shortcut: a detection stuck without reading keeps its goroutine
		// after TIMED_OUT; Phase 6 worker processes give each run a killable
		// process.
		if err := ctx.Err(); err != nil {
			return evaluation{status: RunStatusFailed, err: err}
		}
		return evaluation{status: RunStatusTimedOut, err: fmt.Errorf("evaluation timed out after %s", timeout)}
	}

	if result.panicValue != nil {
		stack := result.stack
		if len(stack) > maxPanicStackBytes {
			stack = stack[:maxPanicStackBytes]
		}
		return evaluation{status: RunStatusFailed, err: fmt.Errorf("panic: %v\n%s", result.panicValue, stack)}
	}
	if result.err != nil {
		if errors.Is(result.err, context.DeadlineExceeded) {
			return evaluation{status: RunStatusTimedOut, err: fmt.Errorf("evaluation timed out after %s: %w", timeout, result.err)}
		}
		return evaluation{status: RunStatusFailed, err: result.err}
	}

	proposals, err := checkProposals(manifest, window, result.proposals)
	if err != nil {
		return evaluation{status: RunStatusFailed, err: err}
	}
	return evaluation{status: RunStatusOK, proposals: proposals}
}

// checkProposals applies the manifest's proposal budgets and rules to one
// evaluation's output. A zero severity takes the manifest's severity.
func checkProposals(manifest config.DetectionManifest, window Window, proposals []Proposal) ([]Proposal, error) {
	if len(proposals) > manifest.Budgets.MaxProposals {
		return nil, fmt.Errorf("proposal count %d exceeds budget %d", len(proposals), manifest.Budgets.MaxProposals)
	}

	checked := slices.Clone(proposals)
	for index := range checked {
		proposal := &checked[index]
		number := index + 1

		if strings.TrimSpace(proposal.Summary) == "" {
			return nil, fmt.Errorf("proposal %d: summary is empty", number)
		}
		if len(proposal.Summary) > maxSummaryBytes {
			return nil, fmt.Errorf("proposal %d: summary is longer than %d bytes", number, maxSummaryBytes)
		}
		if len(proposal.Evidence) == 0 {
			return nil, fmt.Errorf("proposal %d: evidence is empty", number)
		}
		if len(proposal.Evidence) > manifest.Budgets.MaxEvidencePerProposal {
			return nil, fmt.Errorf("proposal %d: evidence count %d exceeds budget %d",
				number, len(proposal.Evidence), manifest.Budgets.MaxEvidencePerProposal)
		}
		for evidenceIndex, evidence := range proposal.Evidence {
			if evidence.EventTime.Before(window.Start) || !evidence.EventTime.Before(window.End) {
				return nil, fmt.Errorf("proposal %d: evidence %d event time %s is outside the window [%s, %s)",
					number, evidenceIndex, evidence.EventTime, window.Start, window.End)
			}
		}

		switch proposal.Severity {
		case "":
			proposal.Severity = Severity(manifest.Severity)
		case SeverityLow, SeverityMedium, SeverityHigh:
		default:
			return nil, fmt.Errorf("proposal %d: invalid severity %q", number, proposal.Severity)
		}

		if len(proposal.Details) > maxDetailEntries {
			return nil, fmt.Errorf("proposal %d: details has %d entries, more than %d",
				number, len(proposal.Details), maxDetailEntries)
		}
		for name, value := range proposal.Details {
			if len(value) > maxDetailValueBytes {
				return nil, fmt.Errorf("proposal %d: detail %q is longer than %d bytes",
					number, name, maxDetailValueBytes)
			}
		}

		if _, err := ComputeIdentity(manifest.ID, manifest.Alerting, proposal.Subject); err != nil {
			return nil, fmt.Errorf("proposal %d: %w", number, err)
		}
	}
	return checked, nil
}

// compareProposals reports every difference between the evaluated proposals
// and the fixture's expectation, in order. An expected identity compares only
// the paths it lists.
func compareProposals(manifest config.DetectionManifest, proposals []Proposal, expected []FixtureProposal) []string {
	var differences []string
	if len(proposals) != len(expected) {
		differences = append(differences, fmt.Sprintf("proposal count: got %d, want %d", len(proposals), len(expected)))
	}

	for index, expectedProposal := range expected {
		if index >= len(proposals) {
			break
		}
		proposal := proposals[index]
		number := index + 1
		identity, err := ComputeIdentity(manifest.ID, manifest.Alerting, proposal.Subject)
		if err != nil {
			differences = append(differences, fmt.Sprintf("proposal %d: identity: %v", number, err))
			continue
		}
		for _, path := range slices.Sorted(maps.Keys(expectedProposal.Identity)) {
			value, exists := identity.Values[path]
			if !exists {
				differences = append(differences, fmt.Sprintf("proposal %d: identity path %s is not a manifest identity field", number, path))
				continue
			}
			if !equalOptional(value, expectedProposal.Identity[path]) {
				differences = append(differences, fmt.Sprintf("proposal %d: identity %s: got %s, want %s",
					number, path, formatOptional(value), formatOptional(expectedProposal.Identity[path])))
			}
		}
		if proposal.Severity != expectedProposal.Severity {
			differences = append(differences, fmt.Sprintf("proposal %d: severity: got %q, want %q",
				number, proposal.Severity, expectedProposal.Severity))
		}
		if len(proposal.Evidence) != expectedProposal.EvidenceCount {
			differences = append(differences, fmt.Sprintf("proposal %d: evidence count: got %d, want %d",
				number, len(proposal.Evidence), expectedProposal.EvidenceCount))
		}
	}
	return differences
}

func equalOptional(first, second *string) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func formatOptional(value *string) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprintf("%q", *value)
}
