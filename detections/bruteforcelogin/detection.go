// Package bruteforcelogin detects a burst of failed logons followed by a
// success for the same account, host, and origin.
package bruteforcelogin

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"

	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// shortcut: no manifest parameters, add when a threshold must change without
// a deploy (worker runtime, Phase 6).
const failedAttemptsThreshold = 10

// maxEvidence must match budgets.maxEvidencePerProposal in detection.yaml;
// the logic cannot read the manifest, so the two are kept in step by hand.
const maxEvidence = 1000

// maxBufferedFailures is the evidence bound: the success needs the last slot.
const maxBufferedFailures = maxEvidence - 1

//go:embed detection.yaml
var manifest []byte

// Registration is the compiled detection: its embedded manifest and its logic.
var Registration = detection.Registration{Manifest: manifest, Logic: Detection{}}

// Detection holds the logic of the example detection.
type Detection struct{}

// attempts accumulates the failures of one account, host, and origin until a
// success consumes them. Only the latest maxEvidence-1 failures are kept as
// evidence: the count supplies the summary, so an arbitrarily long burst costs
// a bounded amount of memory.
type attempts struct {
	failureCount int
	recent       []dataset.Record // ring of the latest failures
	oldest       int              // index of the oldest entry once recent is full
}

// recordFailure counts one failure and keeps it as evidence, dropping the
// oldest kept failure once the ring is full.
func (current *attempts) recordFailure(record dataset.Record) {
	current.failureCount++
	if len(current.recent) < maxBufferedFailures {
		current.recent = append(current.recent, record)
		return
	}
	current.recent[current.oldest] = record
	current.oldest = (current.oldest + 1) % maxBufferedFailures
}

// evidenceOf lists the kept failures oldest first, followed by the success.
func (current *attempts) evidenceOf(success dataset.Record) []detection.Evidence {
	evidence := make([]detection.Evidence, 0, len(current.recent)+1)
	for offset := 0; offset < len(current.recent); offset++ {
		record := current.recent[(current.oldest+offset)%len(current.recent)]
		evidence = append(evidence, detection.EvidenceOf(record))
	}
	return append(evidence, detection.EvidenceOf(success))
}

// Evaluate reports one proposal per burst of at least ten failed logons
// followed by an ALLOW logon from the same origin. Any other action is
// neither a failure nor a success.
func (Detection) Evaluate(ctx context.Context, window detection.Window) ([]detection.Proposal, error) {
	attemptsByKey := map[string]*attempts{}
	var proposals []detection.Proposal

	for record, err := range window.Events(ctx, "auth_events") {
		if err != nil {
			return nil, err
		}
		event := record.Event
		key := event.Target.User.UserID + "|" + event.Target.Hostname + "|" + firstIP(event.Principal)
		current := attemptsByKey[key]
		if current == nil {
			current = &attempts{}
			attemptsByKey[key] = current
		}

		action := event.SecurityResult.Action
		if action == udm.ActionBlock {
			current.recordFailure(record)
			continue
		}
		if action != udm.ActionAllow {
			continue
		}
		if current.failureCount < failedAttemptsThreshold {
			continue
		}
		failedAttempts := current.failureCount
		proposals = append(proposals, detection.Proposal{
			Subject:  event,
			Summary:  fmt.Sprintf("%d failed logons, then a success", failedAttempts),
			Details:  map[string]string{"failed_attempts": strconv.Itoa(failedAttempts)},
			Evidence: current.evidenceOf(record),
		})
		*current = attempts{} // a later burst is a separate proposal
	}
	return proposals, nil
}

// firstIP is the origin of an attempt: the first principal address, if any.
func firstIP(origin udm.Noun) string {
	if len(origin.IP) == 0 {
		return ""
	}
	return origin.IP[0]
}
