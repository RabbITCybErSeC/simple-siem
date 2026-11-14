package converter_test

import (
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

var testNow = time.Date(2026, time.May, 11, 12, 0, 0, 0, time.UTC)

const testRetention = 72 * time.Hour

const convertLoginMapping = `
id: test-login
version: 3
match:
  - field: event.category
    equals: authentication
  - field: process.name
    equals: sshd
constants:
  metadata.event_type: USER_LOGIN
  metadata.vendor_name: TestVendor
fields:
  - to: metadata.event_timestamp
    from: "@timestamp"
  - to: metadata.ingested_timestamp
    from: event.ingested
  - to: metadata.product_event_type
    from: event.action
  - to: target.user.userid
    from: [user.name, related.user]
  - to: target.hostname
    from: host.name
  - to: principal.ip
    from: source.ip
  - to: principal.port
    from: source.port
  - to: security_result.action
    from: event.outcome
    values: { success: ALLOW, failure: BLOCK }
    default: UNKNOWN_ACTION
`

func TestConvertValidLogin(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00.000Z",
		"event": {
			"category": ["authentication"],
			"action": "ssh_login",
			"outcome": "failure",
			"ingested": "2026-05-11T10:01:04.000Z"
		},
		"process": {"name": "sshd"},
		"user": {"name": "Alice"},
		"host": {"name": "WEB01"},
		"source": {"ip": "::ffff:203.0.113.7", "port": 52114}
	}`)

	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.MappingID != "test-login" || result.MappingVersion != 3 {
		t.Errorf("mapping = %q v%d, want test-login v3", result.MappingID, result.MappingVersion)
	}
	if len(result.Errors) != 0 {
		t.Errorf("errors = %v, want none", result.Errors)
	}

	event := result.Event
	if want := time.Date(2026, time.May, 11, 10, 1, 0, 0, time.UTC); !event.Metadata.EventTimestamp.Equal(want) {
		t.Errorf("event timestamp = %v, want %v", event.Metadata.EventTimestamp, want)
	}
	if want := time.Date(2026, time.May, 11, 10, 1, 4, 0, time.UTC); !event.Metadata.IngestedTimestamp.Equal(want) {
		t.Errorf("ingested timestamp = %v, want %v", event.Metadata.IngestedTimestamp, want)
	}
	if event.Metadata.EventType != udm.EventTypeUserLogin {
		t.Errorf("event type = %q, want USER_LOGIN", event.Metadata.EventType)
	}
	if event.Metadata.VendorName != "TestVendor" {
		t.Errorf("vendor = %q, want TestVendor", event.Metadata.VendorName)
	}
	if event.Metadata.ProductEventType != "ssh_login" {
		t.Errorf("product event type = %q, want ssh_login", event.Metadata.ProductEventType)
	}
	if event.Target.User.UserID != "alice" {
		t.Errorf("target user = %q, want alice", event.Target.User.UserID)
	}
	if event.Target.Hostname != "web01" {
		t.Errorf("target hostname = %q, want web01", event.Target.Hostname)
	}
	if len(event.Principal.IP) != 1 || event.Principal.IP[0] != "203.0.113.7" {
		t.Errorf("principal ip = %v, want [203.0.113.7]", event.Principal.IP)
	}
	if event.Principal.Port != 52114 {
		t.Errorf("principal port = %d, want 52114", event.Principal.Port)
	}
	if event.SecurityResult.Action != udm.ActionBlock {
		t.Errorf("action = %q, want BLOCK", event.SecurityResult.Action)
	}
}

func TestConvertFirstNonEmptySource(t *testing.T) {
	mapping := mustParse(t, convertLoginMapping)

	result := convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": ""},
		"related": {"user": ["bob"]},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.Event.Target.User.UserID != "bob" {
		t.Errorf("target user = %q, want bob", result.Event.Target.User.UserID)
	}

	result = convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": "alice"},
		"related": {"user": ["bob"]},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.Event.Target.User.UserID != "alice" {
		t.Errorf("target user = %q, want the first non-empty source alice", result.Event.Target.User.UserID)
	}
}

func TestConvertValuesAndDefault(t *testing.T) {
	mapping := mustParse(t, `
id: values-test
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: GENERIC_EVENT
  security_result.action: ALLOW
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: metadata.vendor_name, from: event.vendor, values: {known: KnownVendor}, default: UnknownVendor}
  - {to: security_result.summary, from: event.outcome, values: {success: ok}}
`)

	result := convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "vendor": "other", "outcome": "other"}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.Event.Metadata.VendorName != "UnknownVendor" {
		t.Errorf("vendor = %q, want the default UnknownVendor", result.Event.Metadata.VendorName)
	}
	if result.Event.SecurityResult.Summary != "" {
		t.Errorf("summary = %q, want unset when no values entry and no default", result.Event.SecurityResult.Summary)
	}

	result = convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "vendor": "known", "outcome": "success"}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.Event.Metadata.VendorName != "KnownVendor" {
		t.Errorf("vendor = %q, want KnownVendor", result.Event.Metadata.VendorName)
	}
	if result.Event.SecurityResult.Summary != "ok" {
		t.Errorf("summary = %q, want ok", result.Event.SecurityResult.Summary)
	}
}

func TestConvertRepeatedAndScalarTargets(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": "alice"},
		"host": {"name": ["web01", "web02"]},
		"source": {"ip": ["203.0.113.7", "2001:db8::1"], "port": 52114}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if got := result.Event.Principal.IP; len(got) != 2 || got[0] != "203.0.113.7" || got[1] != "2001:db8::1" {
		t.Errorf("principal ip = %v, want both addresses in order", got)
	}
	if result.Event.Target.Hostname != "web01" {
		t.Errorf("target hostname = %q, want the first element web01", result.Event.Target.Hostname)
	}
}

func TestConvertTransforms(t *testing.T) {
	mapping := mustParse(t, `
id: transforms-test
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: USER_LOGIN
  metadata.vendor_name: Test
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user.name, transforms: [trim, lowercase, strip_domain]}
  - {to: target.hostname, from: host.name}
  - {to: security_result.action, from: event.outcome, values: {failure: BLOCK}, default: UNKNOWN_ACTION}
`)
	result := convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"user": {"name": "  CORP\\Alice  "},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.Event.Target.User.UserID != "alice" {
		t.Errorf("target user = %q, want alice after trim, lowercase, strip_domain", result.Event.Target.User.UserID)
	}
}

func TestConvertAdditional(t *testing.T) {
	mapping := mustParse(t, `
id: additional-test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
additional:
  - {key: source_country, from: source.geo.country_iso_code, transforms: [trim, lowercase]}
  - {key: workstation, from: winlog.event_data.WorkstationName, transforms: [dash_as_empty]}
`)
	result := convertPayload(t, mapping, `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication"},
		"source": {"geo": {"country_iso_code": " US "}},
		"winlog": {"event_data": {"WorkstationName": "-"}}
	}`)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if got := result.Event.Additional["source_country"]; got != "us" {
		t.Errorf("source_country = %q, want us", got)
	}
	if _, ok := result.Event.Additional["workstation"]; ok {
		t.Errorf("workstation = %q, want the empty transformed value to be skipped", result.Event.Additional["workstation"])
	}
}

func TestConvertPayloadNotAnObject(t *testing.T) {
	cases := []string{
		`[1, 2]`,
		`{"a":`,
		`"text"`,
		`null`,
		``,
		`{"a": 1} {"b": 2}`,
	}
	mapping := mustParse(t, convertLoginMapping)
	for _, payload := range cases {
		result := convertPayload(t, mapping, payload)
		if result.Outcome != converter.OutcomeQuarantined {
			t.Errorf("payload %q outcome = %q, want QUARANTINED", payload, result.Outcome)
		}
		if result.MappingID != "" {
			t.Errorf("payload %q mapping id = %q, want empty", payload, result.MappingID)
		}
		if len(result.Errors) != 1 || result.Errors[0].Path != "payload" {
			t.Errorf("payload %q errors = %v, want one error for payload", payload, result.Errors)
		}
	}
}

func TestConvertUnmapped(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "process", "outcome": "success"},
		"process": {"name": "bash"}
	}`)
	if result.Outcome != converter.OutcomeUnmapped {
		t.Errorf("outcome = %q, want UNMAPPED; errors = %v", result.Outcome, result.Errors)
	}
	if result.MappingID != "" || result.MappingVersion != 0 {
		t.Errorf("mapping = %q v%d, want empty", result.MappingID, result.MappingVersion)
	}
	if len(result.Errors) != 0 {
		t.Errorf("errors = %v, want none", result.Errors)
	}
}

func TestConvertValidationFailure(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Fatalf("outcome = %q, want QUARANTINED", result.Outcome)
	}
	if result.MappingID != "test-login" || result.MappingVersion != 3 {
		t.Errorf("mapping = %q v%d, want test-login v3", result.MappingID, result.MappingVersion)
	}
	if !hasValidationError(result.Errors, "target.user.userid") {
		t.Errorf("errors = %v, want an error for target.user.userid", result.Errors)
	}
}

func TestConvertFieldResolutionError(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": {"first": "alice"}},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Fatalf("outcome = %q, want QUARANTINED", result.Outcome)
	}
	found := false
	for _, problem := range result.Errors {
		if problem.Path == "target.user.userid" && strings.Contains(problem.Message, "from user.name: expected a scalar") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors = %v, want a resolution error for target.user.userid", result.Errors)
	}
}

func TestConvertFieldSetError(t *testing.T) {
	result := convertPayload(t, mustParse(t, convertLoginMapping), `{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": "alice"},
		"host": {"name": "web01"},
		"source": {"ip": "not-an-ip", "port": 52114}
	}`)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Fatalf("outcome = %q, want QUARANTINED", result.Outcome)
	}
	found := false
	for _, problem := range result.Errors {
		if problem.Path == "principal.ip" && strings.Contains(problem.Message, "must be an IP address") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors = %v, want a Set error for principal.ip", result.Errors)
	}
}

func TestConvertFutureEventTime(t *testing.T) {
	payload := `{
		"@timestamp": "` + testNow.Add(25*time.Hour).Format(time.RFC3339) + `",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": "alice"},
		"host": {"name": "web01"}
	}`
	result := convertPayload(t, mustParse(t, convertLoginMapping), payload)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Fatalf("outcome = %q, want QUARANTINED", result.Outcome)
	}
	if !hasValidationError(result.Errors, "metadata.event_timestamp") {
		t.Errorf("errors = %v, want an error for metadata.event_timestamp", result.Errors)
	}
}

func TestConvertLateBeyondRetention(t *testing.T) {
	payload := `{
		"@timestamp": "` + testNow.Add(-73*time.Hour).Format(time.RFC3339) + `",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"user": {"name": "alice"},
		"host": {"name": "web01"}
	}`
	result := convertPayload(t, mustParse(t, convertLoginMapping), payload)
	if result.Outcome != converter.OutcomeLateBeyondRetention {
		t.Fatalf("outcome = %q, want LATE_BEYOND_RETENTION; errors = %v", result.Outcome, result.Errors)
	}
	if result.MappingID != "test-login" || result.MappingVersion != 3 {
		t.Errorf("mapping = %q v%d, want test-login v3", result.MappingID, result.MappingVersion)
	}
	if len(result.Errors) != 0 {
		t.Errorf("errors = %v, want none", result.Errors)
	}
}

func TestConvertTimeBoundaries(t *testing.T) {
	for _, timestamp := range []time.Time{testNow.Add(24 * time.Hour), testNow.Add(-72 * time.Hour)} {
		payload := `{
			"@timestamp": "` + timestamp.Format(time.RFC3339) + `",
			"event": {"category": "authentication", "outcome": "failure"},
			"process": {"name": "sshd"},
			"user": {"name": "alice"},
			"host": {"name": "web01"}
		}`
		result := convertPayload(t, mustParse(t, convertLoginMapping), payload)
		if result.Outcome != converter.OutcomeConverted {
			t.Errorf("event time %v outcome = %q, want CONVERTED; errors = %v", timestamp, result.Outcome, result.Errors)
		}
	}
}

func TestConvertLateButInvalidIsQuarantined(t *testing.T) {
	payload := `{
		"@timestamp": "` + testNow.Add(-73*time.Hour).Format(time.RFC3339) + `",
		"event": {"category": "authentication", "outcome": "failure"},
		"process": {"name": "sshd"},
		"host": {"name": "web01"}
	}`
	result := convertPayload(t, mustParse(t, convertLoginMapping), payload)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Errorf("outcome = %q, want QUARANTINED because validation errors win", result.Outcome)
	}
}

func TestConvertCollectsAndSortsErrors(t *testing.T) {
	mapping := mustParse(t, `
id: errors-test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: USER_LOGIN}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user}
  - {to: target.hostname, from: host}
  - {to: security_result.action, from: event.outcome}
`)
	result := convertPayload(t, mapping, `{
		"@timestamp": "not-a-time",
		"event": {"category": "authentication", "outcome": "allow"},
		"user": {"name": "alice"},
		"host": {"name": "web01"}
	}`)
	if result.Outcome != converter.OutcomeQuarantined {
		t.Fatalf("outcome = %q, want QUARANTINED", result.Outcome)
	}
	if len(result.Errors) < 4 {
		t.Fatalf("errors = %v, want several collected errors", result.Errors)
	}
	for index := 1; index < len(result.Errors); index++ {
		if result.Errors[index-1].Path > result.Errors[index].Path {
			t.Errorf("errors are not sorted by path: %v", result.Errors)
			break
		}
	}
	if !hasValidationError(result.Errors, "metadata.event_timestamp") {
		t.Errorf("errors = %v, want metadata.event_timestamp", result.Errors)
	}
	if !hasValidationError(result.Errors, "target.user.userid") {
		t.Errorf("errors = %v, want target.user.userid", result.Errors)
	}
	if !hasValidationError(result.Errors, "target.hostname") {
		t.Errorf("errors = %v, want target.hostname", result.Errors)
	}
	if !hasValidationError(result.Errors, "security_result.action") {
		t.Errorf("errors = %v, want security_result.action", result.Errors)
	}
}

func TestConvertFirstMatchingMappingWins(t *testing.T) {
	first := mustParse(t, `
id: first
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: GENERIC_EVENT
  metadata.vendor_name: First
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`)
	second := mustParse(t, `
id: second
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: GENERIC_EVENT
  metadata.vendor_name: Second
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`)
	result := converter.New([]converter.Mapping{first, second}, testRetention).Convert([]byte(`{
		"@timestamp": "2026-05-11T10:01:00Z",
		"event": {"category": "authentication"}
	}`), testNow)
	if result.Outcome != converter.OutcomeConverted {
		t.Fatalf("outcome = %q, want CONVERTED; errors = %v", result.Outcome, result.Errors)
	}
	if result.MappingID != "first" {
		t.Errorf("mapping id = %q, want first", result.MappingID)
	}
	if result.Event.Metadata.VendorName != "First" {
		t.Errorf("vendor = %q, want First", result.Event.Metadata.VendorName)
	}
}

func convertPayload(t *testing.T, mapping converter.Mapping, payload string) converter.Result {
	t.Helper()
	return converter.New([]converter.Mapping{mapping}, testRetention).Convert([]byte(payload), testNow)
}

func hasValidationError(errors []udm.ValidationError, path string) bool {
	for _, problem := range errors {
		if problem.Path == path {
			return true
		}
	}
	return false
}
