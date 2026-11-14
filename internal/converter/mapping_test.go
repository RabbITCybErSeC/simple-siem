package converter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
)

const validMappingYAML = `
id: test-login
version: 1
description: test mapping
match:
  - field: event.category
    equals: authentication
constants:
  metadata.event_type: USER_LOGIN
  metadata.vendor_name: TestVendor
fields:
  - to: metadata.event_timestamp
    from: "@timestamp"
  - to: target.user.userid
    from: [user.name, related.user]
  - to: security_result.action
    from: event.outcome
    values: { success: ALLOW, failure: BLOCK }
    default: UNKNOWN_ACTION
additional:
  - key: source_country
    from: source.geo.country_iso_code
`

func TestParseMapping(t *testing.T) {
	mapping := mustParse(t, validMappingYAML)

	if mapping.ID != "test-login" {
		t.Errorf("id = %q, want test-login", mapping.ID)
	}
	if mapping.Version != 1 {
		t.Errorf("version = %d, want 1", mapping.Version)
	}
	if mapping.Description != "test mapping" {
		t.Errorf("description = %q, want test mapping", mapping.Description)
	}
	if len(mapping.Match) != 1 {
		t.Fatalf("match count = %d, want 1", len(mapping.Match))
	}
	condition := mapping.Match[0]
	if condition.Field != "event.category" {
		t.Errorf("match field = %q, want event.category", condition.Field)
	}
	if condition.Equals == nil || *condition.Equals != "authentication" {
		t.Errorf("match equals = %v, want authentication", condition.Equals)
	}
	if condition.In != nil {
		t.Errorf("match in = %v, want nil", condition.In)
	}

	if got := mapping.Constants["metadata.event_type"]; got != "USER_LOGIN" {
		t.Errorf("event type constant = %q, want USER_LOGIN", got)
	}
	if got := mapping.Constants["metadata.vendor_name"]; got != "TestVendor" {
		t.Errorf("vendor constant = %q, want TestVendor", got)
	}

	if len(mapping.Fields) != 3 {
		t.Fatalf("field count = %d, want 3", len(mapping.Fields))
	}
	userID := mapping.Fields[1]
	if userID.To != "target.user.userid" {
		t.Errorf("field to = %q, want target.user.userid", userID.To)
	}
	if !reflect.DeepEqual(userID.From, []string{"user.name", "related.user"}) {
		t.Errorf("field from = %v, want [user.name related.user]", userID.From)
	}
	action := mapping.Fields[2]
	if action.Values["success"] != "ALLOW" || action.Values["failure"] != "BLOCK" {
		t.Errorf("values = %v, want success ALLOW and failure BLOCK", action.Values)
	}
	if action.Default == nil || *action.Default != "UNKNOWN_ACTION" {
		t.Errorf("default = %v, want UNKNOWN_ACTION", action.Default)
	}

	if len(mapping.Additional) != 1 {
		t.Fatalf("additional count = %d, want 1", len(mapping.Additional))
	}
	if mapping.Additional[0].Key != "source_country" {
		t.Errorf("additional key = %q, want source_country", mapping.Additional[0].Key)
	}
	if !reflect.DeepEqual(mapping.Additional[0].From, []string{"source.geo.country_iso_code"}) {
		t.Errorf("additional from = %v, want one scalar path", mapping.Additional[0].From)
	}
}

func TestParseMappingScalarLiterals(t *testing.T) {
	mapping := mustParse(t, `
id: scalar-test
version: 1
match:
  - field: winlog.event_id
    in: [4624, 4625]
  - field: event.category
    equals: 4625
constants:
  metadata.event_type: USER_LOGIN
  metadata.product_log_id: 918273
  metadata.description: true
fields:
  - to: metadata.event_timestamp
    from: "@timestamp"
  - to: security_result.action
    from: event.outcome
    values: { true: ALLOW, 4625: BLOCK }
    default: UNKNOWN_ACTION
`)

	if !reflect.DeepEqual(mapping.Match[0].In, []string{"4624", "4625"}) {
		t.Errorf("in = %v, want [4624 4625]", mapping.Match[0].In)
	}
	if mapping.Match[1].Equals == nil || *mapping.Match[1].Equals != "4625" {
		t.Errorf("equals = %v, want 4625", mapping.Match[1].Equals)
	}
	if mapping.Constants["metadata.product_log_id"] != "918273" {
		t.Errorf("product log id = %q, want 918273", mapping.Constants["metadata.product_log_id"])
	}
	if mapping.Constants["metadata.description"] != "true" {
		t.Errorf("description = %q, want true", mapping.Constants["metadata.description"])
	}
	if mapping.Fields[1].Values["true"] != "ALLOW" || mapping.Fields[1].Values["4625"] != "BLOCK" {
		t.Errorf("values = %v, want true ALLOW and 4625 BLOCK", mapping.Fields[1].Values)
	}
}

func TestParseMappingAcceptsConstantsOnly(t *testing.T) {
	mustParse(t, `
id: constants-only
version: 1
match:
  - field: event.category
    equals: authentication
constants:
  metadata.event_type: GENERIC_EVENT
  metadata.event_timestamp: "2026-05-11T10:01:00Z"
`)
}

func TestParseMappingRejectsInvalidMappings(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []string
	}{
		{
			"unknown top-level key",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
unexpected: true
`,
			[]string{"unknown field"},
		},
		{
			"duplicate top-level key",
			`
id: test
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"already defined"},
		},
		{
			"version is a string",
			`
id: test
version: "1"
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"version", "integer"},
		},
		{
			"id is an integer",
			`
id: 123
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"id", "string"},
		},
		{
			"match is not a list",
			`
id: test
version: 1
match: authentication
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match"},
		},
		{
			"from is an integer",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: 123}]
`,
			[]string{"from", "string"},
		},
		{
			"invalid id",
			`
id: Test_Mapping
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{`mapping "Test_Mapping"`, "id"},
		},
		{
			"version below one",
			`
id: test
version: 0
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"version", "at least 1"},
		},
		{
			"no match conditions",
			`
id: test
version: 1
match: []
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match", "at least one"},
		},
		{
			"condition without field",
			`
id: test
version: 1
match: [{equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match[0].field"},
		},
		{
			"condition with both forms",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication, in: [authentication]}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match[0]", "exactly one"},
		},
		{
			"condition with neither form",
			`
id: test
version: 1
match: [{field: event.category}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match[0]", "exactly one"},
		},
		{
			"empty in list",
			`
id: test
version: 1
match: [{field: event.category, in: []}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match[0]", "exactly one"},
		},
		{
			"in is a scalar",
			`
id: test
version: 1
match: [{field: event.category, in: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"match[0].in"},
		},
		{
			"unknown target field",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: target.user.email, from: user.email}]
`,
			[]string{`mapping "test"`, "target.user.email", "unknown field"},
		},
		{
			"unknown constant path",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT, target.process.pid: "1"}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"target.process.pid", "unknown field"},
		},
		{
			"path set twice across a constant and a field",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: GENERIC_EVENT
  metadata.event_timestamp: "2026-05-11T10:01:00Z"
fields:
  - {to: metadata.event_type, from: event.type}
`,
			[]string{"metadata.event_type", "set more than once"},
		},
		{
			"path set twice by two fields",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: metadata.event_timestamp, from: event.created}
`,
			[]string{"metadata.event_timestamp", "set more than once"},
		},
		{
			"field without from",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp}]
`,
			[]string{"fields[0].from", "at least one"},
		},
		{
			"field with empty from",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: ""}]
`,
			[]string{"fields[0].from"},
		},
		{
			"unknown transform",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp", transforms: [uppercase]}
`,
			[]string{"fields[0].transforms", "uppercase"},
		},
		{
			"invalid constant value",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: LOGIN}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"constants.metadata.event_type", "LOGIN"},
		},
		{
			"invalid values target",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: USER_LOGIN}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user.name}
  - {to: target.hostname, from: host.name}
  - {to: security_result.action, from: event.outcome, values: {success: ALLOWED}}
`,
			[]string{"fields[3].values", "ALLOWED"},
		},
		{
			"invalid default",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: USER_LOGIN}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user.name}
  - {to: target.hostname, from: host.name}
  - {to: security_result.action, from: event.outcome, default: NOPE}
`,
			[]string{"fields[3].default", "NOPE"},
		},
		{
			"invalid additional key",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
additional: [{key: Bad-Key, from: source.country}]
`,
			[]string{"additional[0].key", "Bad-Key"},
		},
		{
			"duplicate additional key",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
additional:
  - {key: source_country, from: source.country}
  - {key: source_country, from: destination.country}
`,
			[]string{"additional[1].key", "duplicate"},
		},
		{
			"additional without from",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
additional: [{key: source_country}]
`,
			[]string{"additional[0].from", "at least one"},
		},
		{
			"missing event type",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"metadata.event_type", "must be set"},
		},
		{
			"missing event timestamp",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
`,
			[]string{"metadata.event_timestamp", "must be set"},
		},
		{
			"unknown nested field",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp", unexpected: true}
`,
			[]string{"unknown field"},
		},
		{
			"duplicate nested key",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields:
  - to: metadata.event_timestamp
    to: metadata.event_timestamp
    from: "@timestamp"
`,
			[]string{"already defined"},
		},
		{
			"non-string values target",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: USER_LOGIN}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user.name}
  - {to: target.hostname, from: host.name}
  - {to: security_result.action, from: event.outcome, values: {success: 1}}
`,
			[]string{"string"},
		},
		{
			"float values key",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: USER_LOGIN}
fields:
  - {to: metadata.event_timestamp, from: "@timestamp"}
  - {to: target.user.userid, from: user.name}
  - {to: target.hostname, from: host.name}
  - {to: security_result.action, from: event.outcome, values: {1.5: ALLOW}}
`,
			[]string{"values", "string, integer, or boolean"},
		},
		{
			"float constant value",
			`
id: test
version: 1
match: [{field: event.category, equals: authentication}]
constants:
  metadata.event_type: GENERIC_EVENT
  metadata.description: 1.5
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"constants.metadata.description", "string, integer, or boolean"},
		},
		{
			"non-string description",
			`
id: test
version: 1
description: 42
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`,
			[]string{"description", "string"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := converter.ParseMapping([]byte(test.data))
			if err == nil {
				t.Fatal("ParseMapping returned nil error")
			}
			for _, want := range test.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestLoadMappingsKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	first := writeMappingFile(t, dir, "first.yaml", minimalMapping("first-mapping"))
	second := writeMappingFile(t, dir, "second.yaml", minimalMapping("second-mapping"))

	mappings, err := converter.LoadMappings([]string{second, first})
	if err != nil {
		t.Fatalf("LoadMappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mapping count = %d, want 2", len(mappings))
	}
	if mappings[0].ID != "second-mapping" || mappings[1].ID != "first-mapping" {
		t.Errorf("ids = [%s %s], want [second-mapping first-mapping]", mappings[0].ID, mappings[1].ID)
	}
}

func TestLoadMappingsRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	first := writeMappingFile(t, dir, "first.yaml", minimalMapping("same-id"))
	second := writeMappingFile(t, dir, "second.yaml", minimalMapping("same-id"))

	_, err := converter.LoadMappings([]string{first, second})
	if err == nil {
		t.Fatal("LoadMappings returned nil error for duplicate ids")
	}
	for _, path := range []string{first, second} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error = %q, want it to name %s", err, path)
		}
	}
}

func TestLoadMappingsRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := writeMappingFile(t, dir, "big.yaml", strings.Repeat("# filler\n", (1<<20)/9+10))

	_, err := converter.LoadMappings([]string{path})
	if err == nil {
		t.Fatal("LoadMappings returned nil error for an oversized file")
	}
	if !strings.Contains(err.Error(), "1048576") {
		t.Errorf("error = %q, want it to mention the 1 MiB limit", err)
	}
}

func TestLoadMappingsWrapsFileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := converter.LoadMappings([]string{path})
	if err == nil {
		t.Fatal("LoadMappings returned nil error for a missing file")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name %s", err, path)
	}
}

func mustParse(t *testing.T, data string) converter.Mapping {
	t.Helper()
	mapping, err := converter.ParseMapping([]byte(data))
	if err != nil {
		t.Fatalf("ParseMapping: %v", err)
	}
	return mapping
}

func minimalMapping(id string) string {
	return fmt.Sprintf(`
id: %s
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`, id)
}

func writeMappingFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
