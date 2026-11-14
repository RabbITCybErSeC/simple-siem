package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

const identityTestDetection = "brute-force-then-success"

func identityAlerting(mode string, fields ...config.IdentityField) config.DetectionAlerting {
	return config.DetectionAlerting{
		Mode:                  mode,
		IdentitySchemaVersion: 1,
		IdentityFields:        fields,
	}
}

func identitySubject(userID string, hostname string, ip string) udm.Event {
	subject := udm.Event{
		Metadata: udm.Metadata{
			EventTimestamp: time.Date(2026, 5, 11, 10, 1, 0, 0, time.UTC),
			EventType:      udm.EventTypeUserLogin,
		},
		Target: udm.Noun{
			User:     udm.User{UserID: userID},
			Hostname: hostname,
		},
	}
	if ip != "" {
		subject.Target.IP = []string{ip}
	}
	return subject
}

func expectedIdentityHash(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func TestComputeIdentity(t *testing.T) {
	userAndHost := identityAlerting("MERGE",
		config.IdentityField{Path: "target.user.userid", Required: true},
		config.IdentityField{Path: "target.hostname", Fallback: "target.ip"},
	)

	tests := []struct {
		name        string
		alerting    config.DetectionAlerting
		subject     udm.Event
		wantValues  map[string]*string
		wantHashFor string
		wantError   string
		wantMissing bool
	}{
		{
			name:     "fallback path supplies an empty optional field",
			alerting: userAndHost,
			subject:  identitySubject("alice", "", "10.0.0.5"),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
				"target.hostname":    pointerTo("10.0.0.5"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.user.userid","alice"],["target.hostname","10.0.0.5"]]}`,
		},
		{
			name:     "present value wins over the fallback",
			alerting: userAndHost,
			subject:  identitySubject("alice", "web01", "10.0.0.5"),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
				"target.hostname":    pointerTo("web01"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.user.userid","alice"],["target.hostname","web01"]]}`,
		},
		{
			name:     "optional field with no value hashes as null",
			alerting: userAndHost,
			subject:  identitySubject("alice", "", ""),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
				"target.hostname":    nil,
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.user.userid","alice"],["target.hostname",null]]}`,
		},
		{
			name:     "values are trimmed",
			alerting: userAndHost,
			subject:  identitySubject("  alice  ", " web01 ", ""),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
				"target.hostname":    pointerTo("web01"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.user.userid","alice"],["target.hostname","web01"]]}`,
		},
		{
			name:        "missing required field fails naming the path",
			alerting:    userAndHost,
			subject:     identitySubject("", "web01", ""),
			wantError:   "target.user.userid",
			wantMissing: true,
		},
		{
			name: "all values null fails for MERGE",
			alerting: identityAlerting("MERGE",
				config.IdentityField{Path: "target.hostname", Fallback: "target.ip"},
			),
			subject:     identitySubject("", "", ""),
			wantError:   "all identity fields are null",
			wantMissing: true,
		},
		{
			name: "all values null is allowed for ALWAYS_NEW",
			alerting: identityAlerting("ALWAYS_NEW",
				config.IdentityField{Path: "target.hostname", Fallback: "target.ip"},
			),
			subject: identitySubject("", "", ""),
			wantValues: map[string]*string{
				"target.hostname": nil,
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.hostname",null]]}`,
		},
		{
			name:     "field order changes the hash",
			alerting: identityAlerting("MERGE", config.IdentityField{Path: "target.hostname"}, config.IdentityField{Path: "target.user.userid", Required: true}),
			subject:  identitySubject("alice", "web01", ""),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
				"target.hostname":    pointerTo("web01"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.hostname","web01"],["target.user.userid","alice"]]}`,
		},
		{
			name:     "canonical IPv6 value is used unchanged",
			alerting: identityAlerting("MERGE", config.IdentityField{Path: "target.ip", Required: true}),
			subject:  identitySubject("alice", "", "2001:db8::1"),
			wantValues: map[string]*string{
				"target.ip": pointerTo("2001:db8::1"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.ip","2001:db8::1"]]}`,
		},
		{
			name:      "unknown identity path is an error",
			alerting:  identityAlerting("MERGE", config.IdentityField{Path: "target.user.email", Required: true}),
			subject:   identitySubject("alice", "web01", ""),
			wantError: "target.user.email",
		},
		{
			name:      "unknown fallback path is an error",
			alerting:  identityAlerting("MERGE", config.IdentityField{Path: "target.hostname", Fallback: "target.domain"}),
			subject:   identitySubject("alice", "", ""),
			wantError: "target.domain",
		},
		{
			name:     "hash input covers only id schema and fields",
			alerting: identityAlerting("MERGE", config.IdentityField{Path: "target.user.userid", Required: true}),
			subject:  identitySubject("alice", "", ""),
			wantValues: map[string]*string{
				"target.user.userid": pointerTo("alice"),
			},
			wantHashFor: `{"detection":"brute-force-then-success","schema":1,"fields":[["target.user.userid","alice"]]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := ComputeIdentity(identityTestDetection, test.alerting, test.subject)

			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("ComputeIdentity() error = %v, want an error containing %q", err, test.wantError)
				}
				if !test.wantMissing {
					return
				}
				if !errors.Is(err, ErrIdentityMissing) {
					t.Fatalf("ComputeIdentity() error = %v, want ErrIdentityMissing", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ComputeIdentity() error = %v, want nil", err)
			}
			if !equalIdentityValues(identity.Values, test.wantValues) {
				t.Fatalf("ComputeIdentity() values = %s, want %s", formatIdentityValues(identity.Values), formatIdentityValues(test.wantValues))
			}
			wantHash := expectedIdentityHash(t, test.wantHashFor)
			if identity.Hash != wantHash {
				t.Fatalf("ComputeIdentity() hash = %s, want %s (input %s)", identity.Hash, wantHash, test.wantHashFor)
			}
		})
	}
}

func pointerTo(value string) *string {
	return &value
}

func equalIdentityValues(first, second map[string]*string) bool {
	if len(first) != len(second) {
		return false
	}
	for path, value := range first {
		other, exists := second[path]
		if !exists {
			return false
		}
		if value == nil || other == nil {
			if value != nil || other != nil {
				return false
			}
			continue
		}
		if *value != *other {
			return false
		}
	}
	return true
}

func formatIdentityValues(values map[string]*string) string {
	var parts []string
	for path, value := range values {
		if value == nil {
			parts = append(parts, path+"=null")
			continue
		}
		parts = append(parts, path+"="+*value)
	}
	return strings.Join(parts, " ")
}
