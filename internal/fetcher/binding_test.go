package fetcher

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
)

func TestBindTypes(t *testing.T) {
	rawQuery := map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}},
			map[string]any{"term": map[string]any{"user.id": "${parameters.id}"}},
			map[string]any{"term": map[string]any{"event.success": "${parameters.success}"}},
			map[string]any{"range": map[string]any{"event.ingested": map[string]any{
				"gte":    "${parameters.since}",
				"format": "strict_date_optional_time_nanos",
			}}},
		}}},
	}
	parameters := map[string]config.TemplateParameter{
		"user":    {Type: "string", Required: true},
		"id":      {Type: "int", Required: true},
		"success": {Type: "bool", Required: true},
		"since":   {Type: "timestamp", Required: true},
	}
	values := map[string]string{
		"user":    "root",
		"id":      "42",
		"success": "true",
		"since":   "2026-11-13T10:00:00.123456789+02:00",
	}

	bound, err := Bind(rawQuery, parameters, values)
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}

	filter := boundFilter(t, bound)
	if len(filter) != 4 {
		t.Fatalf("filter clauses = %d, want 4", len(filter))
	}
	checks := []struct {
		clause any
		field  string
		want   any
	}{
		{filter[0], "user.name", "root"},
		{filter[1], "user.id", int64(42)},
		{filter[2], "event.success", true},
	}
	for _, check := range checks {
		if got := termField(t, check.clause, check.field); got != check.want {
			t.Errorf("%s = %#v, want %#v", check.field, got, check.want)
		}
	}

	ingested := mapField(t, mapField(t, filter[3], "range"), "event.ingested")
	if got, want := mapField(t, ingested, "gte"), "2026-11-13T08:00:00.123456789Z"; got != want {
		t.Errorf("range.gte = %#v, want %#v", got, want)
	}
	if got, want := mapField(t, ingested, "format"), "strict_date_optional_time_nanos"; got != want {
		t.Errorf("range.format = %#v, want %#v", got, want)
	}
}

func TestBindRejectsUnparsableValues(t *testing.T) {
	cases := []struct {
		name          string
		parameterType string
		value         string
		reason        string
	}{
		{name: "int", parameterType: "int", value: "1 OR 1", reason: "invalid int"},
		{name: "bool", parameterType: "bool", value: "yes", reason: "invalid bool"},
		{name: "timestamp", parameterType: "timestamp", value: "2026-11-13", reason: "invalid timestamp"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.name": "${parameters.input}"}}}
			parameters := map[string]config.TemplateParameter{"input": {Type: testCase.parameterType, Required: true}}

			_, err := Bind(rawQuery, parameters, map[string]string{"input": testCase.value})
			if err == nil {
				t.Fatalf("Bind() error = nil, want %s error", testCase.reason)
			}
			if !strings.Contains(err.Error(), "input") {
				t.Errorf("Bind() error = %q, want it to name parameter input", err)
			}
			if !strings.Contains(err.Error(), testCase.reason) {
				t.Errorf("Bind() error = %q, want %q", err, testCase.reason)
			}
		})
	}
}

func TestBindErrorTruncatesLongValue(t *testing.T) {
	value := strings.Repeat("A", 10*1024)
	rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.id": "${parameters.id}"}}}
	parameters := map[string]config.TemplateParameter{"id": {Type: "int", Required: true}}

	_, err := Bind(rawQuery, parameters, map[string]string{"id": value})
	if err == nil {
		t.Fatal("Bind() error = nil, want invalid int error")
	}
	if strings.Contains(err.Error(), strings.Repeat("A", 65)) {
		t.Errorf("Bind() error echoes more than 64 bytes of the value: %q", err)
	}
	if len(err.Error()) > 256 {
		t.Errorf("Bind() error length = %d, want a bounded message", len(err.Error()))
	}
}

func TestBindRejectsUnknownAndMissingValues(t *testing.T) {
	rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}}}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string", Required: true}}

	t.Run("unknown value", func(t *testing.T) {
		_, err := Bind(rawQuery, parameters, map[string]string{"user": "root", "other": "x"})
		if err == nil {
			t.Fatal("Bind() error = nil, want unknown parameter error")
		}
		if !strings.Contains(err.Error(), "other") {
			t.Errorf("Bind() error = %q, want it to name parameter other", err)
		}
	})

	t.Run("missing required value", func(t *testing.T) {
		_, err := Bind(rawQuery, parameters, map[string]string{})
		if err == nil {
			t.Fatal("Bind() error = nil, want required parameter error")
		}
		if !strings.Contains(err.Error(), "user") {
			t.Errorf("Bind() error = %q, want it to name parameter user", err)
		}
	})
}

func TestBindRemovesClauseForUnsetOptional(t *testing.T) {
	rawQuery := func() map[string]any {
		return map[string]any{
			"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"term": map[string]any{"event.category": "authentication"}},
				map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}},
			}}},
		}
	}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string"}}

	t.Run("unset", func(t *testing.T) {
		bound, err := Bind(rawQuery(), parameters, map[string]string{})
		if err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		filter := boundFilter(t, bound)
		if len(filter) != 1 {
			t.Fatalf("filter clauses = %d, want 1", len(filter))
		}
		if got := termField(t, filter[0], "event.category"); got != "authentication" {
			t.Errorf("event.category = %#v, want authentication", got)
		}
	})

	t.Run("set", func(t *testing.T) {
		bound, err := Bind(rawQuery(), parameters, map[string]string{"user": "root"})
		if err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		filter := boundFilter(t, bound)
		if len(filter) != 2 {
			t.Fatalf("filter clauses = %d, want 2", len(filter))
		}
		if got := termField(t, filter[1], "user.name"); got != "root" {
			t.Errorf("user.name = %#v, want root", got)
		}
	})
}

func TestBindRemovesNearestEnclosingListElement(t *testing.T) {
	rawQuery := map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"bool": map[string]any{"must": []any{
				map[string]any{"term": map[string]any{"event.category": "authentication"}},
				map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}},
			}}},
		}}},
	}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string"}}

	bound, err := Bind(rawQuery, parameters, map[string]string{})
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	filter := boundFilter(t, bound)
	if len(filter) != 1 {
		t.Fatalf("filter clauses = %d, want 1", len(filter))
	}
	mustNode := mapField(t, mapField(t, filter[0], "bool"), "must")
	must, ok := mustNode.([]any)
	if !ok {
		t.Fatalf("bool.must = %T, want list", mustNode)
	}
	if len(must) != 1 {
		t.Fatalf("bool.must clauses = %d, want 1", len(must))
	}
	if got := termField(t, must[0], "event.category"); got != "authentication" {
		t.Errorf("event.category = %#v, want authentication", got)
	}
}

func TestBindRejectsUnsetOptionalOutsideList(t *testing.T) {
	rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}}}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string"}}

	_, err := Bind(rawQuery, parameters, map[string]string{})
	if err == nil {
		t.Fatal("Bind() error = nil, want unset optional outside a list error")
	}
	if !strings.Contains(err.Error(), "user") {
		t.Errorf("Bind() error = %q, want it to name parameter user", err)
	}
}

func TestBindKeepsHostileStringsAsStrings(t *testing.T) {
	hostile := []struct {
		name  string
		value string
	}{
		{name: "json fragment", value: `"}}, {"script": {"source": "1"}}`},
		{name: "wildcard", value: "*"},
		{name: "10 KB string", value: strings.Repeat("x", 10*1024)},
		{name: "placeholder text", value: "${parameters.other}"},
	}
	parameters := map[string]config.TemplateParameter{
		"user":  {Type: "string", Required: true},
		"other": {Type: "string"},
	}
	for _, testCase := range hostile {
		t.Run(testCase.name, func(t *testing.T) {
			rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}}}

			bound, err := Bind(rawQuery, parameters, map[string]string{"user": testCase.value})
			if err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			query, ok := bound["query"].(map[string]any)
			if !ok {
				t.Fatalf("query = %T, want object", bound["query"])
			}
			if len(query) != 1 {
				t.Errorf("query keys = %d, want 1", len(query))
			}
			if got := termField(t, query, "user.name"); got != testCase.value {
				t.Errorf("bound value = %#v, want the literal string", got)
			}
		})
	}
}

func TestBindDoesNotChangeOrAliasInput(t *testing.T) {
	rawQuery := map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"event.category": "authentication"}},
			map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}},
		}}},
	}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string", Required: true}}
	before := marshalJSON(t, rawQuery)

	bound, err := Bind(rawQuery, parameters, map[string]string{"user": "root"})
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if after := marshalJSON(t, rawQuery); after != before {
		t.Errorf("rawQuery changed after Bind:\nbefore: %s\nafter:  %s", before, after)
	}

	filter := boundFilter(t, bound)
	clause, ok := filter[0].(map[string]any)
	if !ok {
		t.Fatalf("filter[0] = %T, want object", filter[0])
	}
	term, ok := clause["term"].(map[string]any)
	if !ok {
		t.Fatalf("filter[0].term = %T, want object", clause["term"])
	}
	term["event.category"] = "mutated"
	if after := marshalJSON(t, rawQuery); after != before {
		t.Errorf("rawQuery changed through the bound tree:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestRenderedHash(t *testing.T) {
	first := map[string]any{
		"query": map[string]any{"term": map[string]any{"user.name": "root"}},
		"size":  int64(10),
	}
	second := map[string]any{
		"size":  int64(10),
		"query": map[string]any{"term": map[string]any{"user.name": "root"}},
	}
	changed := map[string]any{
		"query": map[string]any{"term": map[string]any{"user.name": "admin"}},
		"size":  int64(10),
	}

	hash := RenderedHash(first)
	if len(hash) != 64 {
		t.Fatalf("RenderedHash() length = %d, want 64 hex characters", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Fatalf("RenderedHash() = %q, want hex", hash)
	}
	if other := RenderedHash(second); other != hash {
		t.Errorf("RenderedHash() is not key-order stable: %q != %q", other, hash)
	}
	if other := RenderedHash(changed); other == hash {
		t.Errorf("RenderedHash() does not change with a bound value: %q", other)
	}
}

func TestRenderedHashCanonicalJSON(t *testing.T) {
	body := map[string]any{"b": 2, "a": 1}
	if got, want := RenderedHash(body), "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"; got != want {
		t.Errorf("RenderedHash() = %q, want the SHA-256 of canonical JSON %q", got, want)
	}
}

func TestRenderedHashFromBoundQuery(t *testing.T) {
	rawQuery := map[string]any{"query": map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}}}
	parameters := map[string]config.TemplateParameter{"user": {Type: "string", Required: true}}

	first, err := Bind(rawQuery, parameters, map[string]string{"user": "root"})
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	second, err := Bind(rawQuery, parameters, map[string]string{"user": "root"})
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	other, err := Bind(rawQuery, parameters, map[string]string{"user": "admin"})
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}

	if RenderedHash(first) != RenderedHash(second) {
		t.Error("RenderedHash() differs for the same template and values")
	}
	if RenderedHash(first) == RenderedHash(other) {
		t.Error("RenderedHash() is the same for a different bound value")
	}
}

func boundFilter(t *testing.T, body map[string]any) []any {
	t.Helper()
	query, ok := body["query"].(map[string]any)
	if !ok {
		t.Fatalf("query = %T, want object", body["query"])
	}
	boolQuery, ok := query["bool"].(map[string]any)
	if !ok {
		t.Fatalf("query.bool = %T, want object", query["bool"])
	}
	filter, ok := boolQuery["filter"].([]any)
	if !ok {
		t.Fatalf("query.bool.filter = %T, want list", boolQuery["filter"])
	}
	return filter
}

func termField(t *testing.T, clause any, field string) any {
	t.Helper()
	return mapField(t, mapField(t, clause, "term"), field)
}

func mapField(t *testing.T, node any, key string) any {
	t.Helper()
	values, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("node = %T, want object with key %q", node, key)
	}
	value, ok := values[key]
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	return value
}

func marshalJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
}
