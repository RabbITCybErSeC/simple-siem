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

//go:embed detection.yaml
var manifest []byte

// Registration is the compiled detection: its embedded manifest and its logic.
var Registration = detection.Registration{Manifest: manifest, Logic: Detection{}}

// Detection holds the logic of the example detection.
type Detection struct{}

// attempts accumulates the failures of one account, host, and origin until a
// success consumes them.
type attempts struct {
	failures []dataset.Record
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
			current.failures = append(current.failures, record)
			continue
		}
		if action != udm.ActionAllow {
			continue
		}
		if len(current.failures) < failedAttemptsThreshold {
			continue
		}
		failedAttempts := len(current.failures)
		proposals = append(proposals, detection.Proposal{
			Subject:  event,
			Summary:  fmt.Sprintf("%d failed logons, then a success", failedAttempts),
			Details:  map[string]string{"failed_attempts": strconv.Itoa(failedAttempts)},
			Evidence: evidenceOf(current.failures, record),
		})
		current.failures = nil // a later burst is a separate proposal
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

// evidenceOf lists the most recent failures of a burst followed by its
// success, capped so the proposal fits maxEvidence. The failure count and the
// summary still carry the real total.
func evidenceOf(failures []dataset.Record, success dataset.Record) []detection.Evidence {
	if len(failures) > maxEvidence-1 {
		failures = failures[len(failures)-(maxEvidence-1):]
	}
	evidence := make([]detection.Evidence, 0, len(failures)+1)
	for _, failure := range failures {
		evidence = append(evidence, detection.EvidenceOf(failure))
	}
	return append(evidence, detection.EvidenceOf(success))
}
