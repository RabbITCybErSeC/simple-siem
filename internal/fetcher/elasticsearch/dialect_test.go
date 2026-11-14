package elasticsearch

import (
	"strings"
	"testing"
)

func TestValidateQueryAcceptsAllowedNodes(t *testing.T) {
	allowed := []struct {
		name     string
		rawQuery map[string]any
	}{
		{
			name:     "term scalar",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"event.category": "authentication"}}},
		},
		{
			name: "term options",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{
				"user.name": map[string]any{"value": "root", "boost": 1, "case_insensitive": true},
			}}},
		},
		{
			name: "bool clauses and minimum_should_match",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{
				"must":                 map[string]any{"term": map[string]any{"user.name": "root"}},
				"filter":               []any{map[string]any{"term": map[string]any{"event.category": "authentication"}}, map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-1h"}}}},
				"should":               []any{map[string]any{"match": map[string]any{"message": "failed"}}},
				"must_not":             map[string]any{"exists": map[string]any{"field": "user.email"}},
				"minimum_should_match": 1,
			}}},
		},
		{
			name: "minimum_should_match string",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{
				"should":               []any{map[string]any{"prefix": map[string]any{"host.name": "web"}}},
				"minimum_should_match": "75%",
			}}},
		},
		{
			name: "terms list and boost",
			rawQuery: map[string]any{"query": map[string]any{"terms": map[string]any{
				"user.name": []any{"alice", "bob"},
				"boost":     2,
			}}},
		},
		{
			name: "range options",
			rawQuery: map[string]any{"query": map[string]any{"range": map[string]any{
				"@timestamp": map[string]any{
					"gte": "2026-11-13T10:00:00Z", "gt": "2026-11-13T09:00:00Z",
					"lte": "2026-11-13T11:00:00Z", "lt": "2026-11-13T12:00:00Z",
					"format": "strict_date_optional_time_nanos", "time_zone": "+01:00",
				},
			}}},
		},
		{
			name: "match_phrase query object",
			rawQuery: map[string]any{"query": map[string]any{"match_phrase": map[string]any{
				"message": map[string]any{"query": "failed password", "operator": "and", "boost": 1.5},
			}}},
		},
		{
			name: "exists, ids, and the _id field",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"exists": map[string]any{"field": "user.name"}},
				map[string]any{"ids": map[string]any{"values": []any{"abc", "def"}}},
				map[string]any{"term": map[string]any{"_id": "abc"}},
			}}}},
		},
		{
			name: "source list",
			rawQuery: map[string]any{
				"query":   map[string]any{"term": map[string]any{"event.category": "authentication"}},
				"_source": []any{"@timestamp", "user.name"},
			},
		},
		{
			name: "source object",
			rawQuery: map[string]any{
				"query":   map[string]any{"term": map[string]any{"event.category": "authentication"}},
				"_source": map[string]any{"includes": []any{"@timestamp", "user.*"}, "excludes": []any{"message"}},
			},
		},
	}

	for _, test := range allowed {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateQuery(test.rawQuery); err != nil {
				t.Errorf("ValidateQuery() error = %v, want nil", err)
			}
		})
	}
}

func TestValidateQueryRejectsDisallowedNodes(t *testing.T) {
	disallowed := []struct {
		name     string
		rawQuery map[string]any
		wantPath string
	}{
		{
			name:     "top-level sort",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "sort": []any{}},
			wantPath: "sort",
		},
		{
			name:     "top-level size",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "size": 10},
			wantPath: "size",
		},
		{
			name:     "top-level pit",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "pit": map[string]any{"id": "x"}},
			wantPath: "pit",
		},
		{
			name:     "top-level aggs",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "aggs": map[string]any{}},
			wantPath: "aggs",
		},
		{
			name: "script in a filter element",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"term": map[string]any{"event.category": "authentication"}},
				map[string]any{"script": map[string]any{"source": "1"}},
			}}}},
			wantPath: "query.bool.filter[1].script",
		},
		{
			name: "terms lookup",
			rawQuery: map[string]any{"query": map[string]any{"terms": map[string]any{
				"user.name": map[string]any{"index": "users", "id": "1", "path": "names"},
			}}},
			wantPath: "query.terms.user.name",
		},
		{
			name:     "query_string",
			rawQuery: map[string]any{"query": map[string]any{"query_string": map[string]any{"query": "*"}}},
			wantPath: "query.query_string",
		},
		{
			name:     "unknown node",
			rawQuery: map[string]any{"query": map[string]any{"wildcard": map[string]any{"a": "b"}}},
			wantPath: "query.wildcard",
		},
		{
			name:     "node with two query keys",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}, "exists": map[string]any{"field": "c"}}},
			wantPath: "query.term",
		},
		{
			name:     "underscore field",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"_routing": "x"}}},
			wantPath: "query.term._routing",
		},
		{
			name:     "bool clause is not a node",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{"must": "script"}}},
			wantPath: "query.bool.must",
		},
		{
			name:     "bool unknown key",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{"minimum_should_match": 1, "script": "x"}}},
			wantPath: "query.bool.script",
		},
		{
			name: "minimum_should_match is not an int",
			rawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{
				"minimum_should_match": true,
			}}},
			wantPath: "query.bool.minimum_should_match",
		},
		{
			name:     "term with a list value",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": []any{"b"}}}},
			wantPath: "query.term.a",
		},
		{
			name: "term option unknown",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{
				"a": map[string]any{"script": "1"},
			}}},
			wantPath: "query.term.a.script",
		},
		{
			name:     "terms values contain an object",
			rawQuery: map[string]any{"query": map[string]any{"terms": map[string]any{"a": []any{map[string]any{"id": "1"}}}}},
			wantPath: "query.terms.a[0]",
		},
		{
			name: "range option unknown",
			rawQuery: map[string]any{"query": map[string]any{"range": map[string]any{
				"@timestamp": map[string]any{"boost": 1},
			}}},
			wantPath: "query.range.@timestamp.boost",
		},
		{
			name:     "exists without field",
			rawQuery: map[string]any{"query": map[string]any{"exists": map[string]any{}}},
			wantPath: "query.exists.field",
		},
		{
			name:     "exists field is not a string",
			rawQuery: map[string]any{"query": map[string]any{"exists": map[string]any{"field": 7}}},
			wantPath: "query.exists.field",
		},
		{
			name:     "ids values is not a list",
			rawQuery: map[string]any{"query": map[string]any{"ids": map[string]any{"values": "abc"}}},
			wantPath: "query.ids.values",
		},
		{
			name:     "missing query",
			rawQuery: map[string]any{"_source": []any{"a"}},
			wantPath: "query",
		},
		{
			name:     "query is not an object",
			rawQuery: map[string]any{"query": "term"},
			wantPath: "query",
		},
		{
			name:     "source element is not a string",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "_source": []any{1}},
			wantPath: "_source[0]",
		},
		{
			name:     "source option unknown",
			rawQuery: map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}, "_source": map[string]any{"include": []any{"a"}}},
			wantPath: "_source.include",
		},
	}

	for _, test := range disallowed {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateQuery(test.rawQuery)
			if err == nil {
				t.Fatalf("ValidateQuery() error = nil, want an error naming %q", test.wantPath)
			}
			if !strings.Contains(err.Error(), test.wantPath) {
				t.Errorf("ValidateQuery() error = %q, want it to name %q", err, test.wantPath)
			}
		})
	}
}
