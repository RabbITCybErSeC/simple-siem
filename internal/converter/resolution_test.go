package converter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		name      string
		payload   string
		path      string
		want      []string
		wantError bool
	}{
		{"literal dotted key", `{"user.name": "alice"}`, "user.name", []string{"alice"}, false},
		{"nested object", `{"user": {"name": "alice"}}`, "user.name", []string{"alice"}, false},
		{"literal key below nested object", `{"winlog": {"event_data.TargetUserName": "alice"}}`, "winlog.event_data.TargetUserName", []string{"alice"}, false},
		{"longest literal key wins", `{"a.b": "outer", "a": {"b": "inner"}}`, "a.b", []string{"outer"}, false},
		{"nested key is found when no literal key exists", `{"a": {"b": "inner"}}`, "a.b", []string{"inner"}, false},
		{"null literal key falls back", `{"a.b": null, "a": {"b": "inner"}}`, "a.b", []string{"inner"}, false},
		{"exact integer", `{"winlog": {"event_id": 4625}}`, "winlog.event_id", []string{"4625"}, false},
		{"large exact integer", `{"n": 12345678901234567890}`, "n", []string{"12345678901234567890"}, false},
		{"decimal keeps its literal text", `{"n": 1.50}`, "n", []string{"1.50"}, false},
		{"true", `{"flag": true}`, "flag", []string{"true"}, false},
		{"false", `{"flag": false}`, "flag", []string{"false"}, false},
		{"null is missing", `{"value": null}`, "value", nil, false},
		{"missing path", `{"user": {"name": "alice"}}`, "user.email", nil, false},
		{"empty string is a value", `{"user": {"name": ""}}`, "user.name", []string{""}, false},
		{"array elements", `{"event": {"category": ["authentication", "session"]}}`, "event.category", []string{"authentication", "session"}, false},
		{"array null elements are skipped", `{"event": {"category": ["a", null, "b"]}}`, "event.category", []string{"a", "b"}, false},
		{"empty array", `{"event": {"category": []}}`, "event.category", nil, false},
		{"scalar with remaining segments", `{"user": "alice"}`, "user.name", nil, false},
		{"object where a scalar is needed", `{"user": {"name": {"first": "alice"}}}`, "user.name", nil, true},
		{"dotted key holding an object", `{"user.name": {"first": "alice"}}`, "user.name", nil, true},
		{"array holding an object", `{"user": {"name": [{"first": "alice"}]}}`, "user.name", nil, true},
		{"array holding an array", `{"user": {"name": [["alice"]]}}`, "user.name", nil, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSegments(decodeTestObject(t, test.payload), strings.Split(test.path, "."))
			if test.wantError {
				if err == nil {
					t.Fatalf("resolve(%q) = %v, want an error", test.path, got)
				}
				if err.Error() != "expected a scalar" {
					t.Errorf("error = %q, want expected a scalar", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%q): %v", test.path, err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("resolve(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	equals := func(value string) *string { return &value }
	cases := []struct {
		name    string
		mapping Mapping
		payload string
		want    bool
	}{
		{
			"equals holds",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {"category": "authentication"}}`,
			true,
		},
		{
			"equals is case sensitive",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {"category": "Authentication"}}`,
			false,
		},
		{
			"equals matches any array element",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {"category": ["session", "authentication"]}}`,
			true,
		},
		{
			"equals does not match another array element",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {"category": ["session", "process"]}}`,
			false,
		},
		{
			"in holds one value",
			Mapping{Match: []Condition{{Field: "winlog.event_id", In: []string{"4624", "4625"}}}},
			`{"winlog": {"event_id": 4625}}`,
			true,
		},
		{
			"in holds another value",
			Mapping{Match: []Condition{{Field: "winlog.event_id", In: []string{"4624", "4625"}}}},
			`{"winlog": {"event_id": "4624"}}`,
			true,
		},
		{
			"in matches any array element",
			Mapping{Match: []Condition{{Field: "event.category", In: []string{"authentication"}}}},
			`{"event": {"category": ["process", "authentication"]}}`,
			true,
		},
		{
			"in misses",
			Mapping{Match: []Condition{{Field: "winlog.event_id", In: []string{"4624", "4625"}}}},
			`{"winlog": {"event_id": 4626}}`,
			false,
		},
		{
			"missing field never matches",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {}}`,
			false,
		},
		{
			"null never matches",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("")}}},
			`{"event": {"category": null}}`,
			false,
		},
		{
			"object never matches",
			Mapping{Match: []Condition{{Field: "event.category", Equals: equals("authentication")}}},
			`{"event": {"category": {"name": "authentication"}}}`,
			false,
		},
		{
			"all conditions must hold",
			Mapping{Match: []Condition{
				{Field: "event.category", Equals: equals("authentication")},
				{Field: "process.name", Equals: equals("sshd")},
			}},
			`{"event": {"category": "authentication"}, "process": {"name": "sshd"}}`,
			true,
		},
		{
			"one false condition is enough",
			Mapping{Match: []Condition{
				{Field: "event.category", Equals: equals("authentication")},
				{Field: "process.name", Equals: equals("sshd")},
			}},
			`{"event": {"category": "authentication"}, "process": {"name": "bash"}}`,
			false,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := compileMapping(test.mapping)
			if err != nil {
				t.Fatalf("compileMapping: %v", err)
			}
			object := decodeTestObject(t, test.payload)
			if got := matches(compiled, object); got != test.want {
				t.Errorf("matches = %v, want %v", got, test.want)
			}
		})
	}
}

func decodeTestObject(t *testing.T, payload string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return object
}
