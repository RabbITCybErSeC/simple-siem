package udm_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

func TestLookupKnownPath(t *testing.T) {
	field, ok := udm.Lookup("target.user.userid")
	if !ok {
		t.Fatal("Lookup(target.user.userid) not found")
	}
	if field.Path != "target.user.userid" {
		t.Errorf("path = %q, want target.user.userid", field.Path)
	}
	if field.Kind != udm.KindUserID {
		t.Errorf("kind = %q, want %q", field.Kind, udm.KindUserID)
	}
	if field.Values != nil {
		t.Errorf("values = %v, want nil for a non-enum field", field.Values)
	}
	if field.Get == nil || field.Set == nil {
		t.Error("field has no getter or setter")
	}
}

func TestLookupEnumValues(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"metadata.event_type", []string{"USER_LOGIN", "USER_LOGOUT", "GENERIC_EVENT"}},
		{"network.application_protocol", []string{"SSH", "RDP", "KRB5", "LDAP", "HTTP", "HTTPS", "UNKNOWN_APPLICATION_PROTOCOL"}},
		{"extensions.auth.mechanism", []string{"USERNAME_PASSWORD", "NETWORK", "INTERACTIVE", "REMOTE_INTERACTIVE", "MECHANISM_OTHER"}},
		{"security_result.action", []string{"ALLOW", "BLOCK", "UNKNOWN_ACTION"}},
	}
	for _, test := range cases {
		t.Run(test.path, func(t *testing.T) {
			field, ok := udm.Lookup(test.path)
			if !ok {
				t.Fatalf("Lookup(%q) not found", test.path)
			}
			if field.Kind != udm.KindEnum {
				t.Errorf("kind = %q, want %q", field.Kind, udm.KindEnum)
			}
			if !reflect.DeepEqual(field.Values, test.want) {
				t.Errorf("values = %v, want %v", field.Values, test.want)
			}
		})
	}
}

func TestLookupUnknownPath(t *testing.T) {
	paths := []string{
		"",
		"target.process.pid",
		"principal.application",
		"principal.user.windows_sid",
		"additional.",
		"additional.1st",
		"additional.Bad-Key",
		"additional.a.b",
		"additional." + strings.Repeat("a", 65),
	}
	for _, path := range paths {
		if field, ok := udm.Lookup(path); ok {
			t.Errorf("Lookup(%q) = %q, want not found", path, field.Path)
		}
	}
}

func TestLookupAdditionalPath(t *testing.T) {
	field, ok := udm.Lookup("additional.source_country")
	if !ok {
		t.Fatal("Lookup(additional.source_country) not found")
	}
	if field.Path != "additional.source_country" {
		t.Errorf("path = %q, want additional.source_country", field.Path)
	}
	if field.Kind != udm.KindString {
		t.Errorf("kind = %q, want %q", field.Kind, udm.KindString)
	}

	event := udm.Event{}
	if err := field.Set(&event, " US "); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := event.Additional["source_country"]; got != "US" {
		t.Errorf("stored value = %q, want US", got)
	}
	value, ok := field.Get(&event)
	if !ok || value != "US" {
		t.Errorf("Get = %q, %v; want US, true", value, ok)
	}
}

func TestCatalogEntriesRoundTrip(t *testing.T) {
	fields := udm.Fields()
	if len(fields) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, field := range fields {
		t.Run(field.Path, func(t *testing.T) {
			if _, ok := field.Get(&udm.Event{}); ok {
				t.Fatalf("%s reports set on a zero event", field.Path)
			}
			want := sampleValue(t, field)
			event := udm.Event{}
			if err := field.Set(&event, want); err != nil {
				t.Fatalf("Set(%q): %v", want, err)
			}
			got, ok := field.Get(&event)
			if !ok {
				t.Fatalf("%s is not set after Set", field.Path)
			}
			if got != want {
				t.Errorf("Get = %q, want %q", got, want)
			}
		})
	}
}

func TestCatalogCoversEvent(t *testing.T) {
	leaves := map[string]struct{}{}
	collectLeafPaths(reflect.TypeOf(udm.Event{}), "", leaves)

	outsideSubset := map[string]bool{
		"principal.application":      true,
		"principal.user.windows_sid": true,
	}
	for path := range leaves {
		if path == "additional" || outsideSubset[path] {
			continue
		}
		if _, ok := udm.Lookup(path); !ok {
			t.Errorf("Event leaf %q has no catalog entry", path)
		}
	}

	seen := map[string]bool{}
	for _, field := range udm.Fields() {
		if seen[field.Path] {
			t.Errorf("duplicate catalog entry %q", field.Path)
		}
		seen[field.Path] = true
		if _, ok := leaves[field.Path]; !ok {
			t.Errorf("catalog path %q is not an Event leaf", field.Path)
		}
	}
}

func TestSetNormalizesByKind(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		value     string
		want      string
		wantError string
	}{
		{"user id trimmed and lowercased", "target.user.userid", " Alice ", "alice", ""},
		{"hostname trimmed, lowercased, trailing dot dropped", "principal.hostname", " Web01.Example. ", "web01.example", ""},
		{"hostname rejects whitespace", "principal.hostname", "web 01", "", "whitespace"},
		{"hostname rejects control characters", "principal.hostname", "web\x01", "", "control"},
		{"mapped IPv4 unmapped", "principal.ip", "::ffff:203.0.113.7", "203.0.113.7", ""},
		{"IPv6 canonicalized", "target.ip", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", ""},
		{"IP zone rejected", "principal.ip", "fe80::1%eth0", "", "zone"},
		{"port upper bound", "principal.port", "65535", "65535", ""},
		{"port above range", "principal.port", "65536", "", "port"},
		{"port below range", "target.port", "-1", "", "port"},
		{"port not a number", "target.port", "http", "", "port"},
		{"RFC 3339 offset converted to UTC", "metadata.event_timestamp", "2026-05-11T12:01:00+02:00", "2026-05-11T10:01:00Z", ""},
		{"timestamp fraction trimmed", "metadata.ingested_timestamp", "2026-05-11T10:01:00.100Z", "2026-05-11T10:01:00.1Z", ""},
		{"epoch milliseconds", "metadata.event_timestamp", "1778493660000", "2026-05-11T10:01:00Z", ""},
		{"invalid timestamp", "metadata.event_timestamp", "not-a-time", "", "RFC 3339"},
		{"enum exact match", "security_result.action", "ALLOW", "ALLOW", ""},
		{"enum trimmed then matched", "network.application_protocol", " SSH ", "SSH", ""},
		{"enum rejects wrong case", "security_result.action", "allow", "", "ALLOW, BLOCK, UNKNOWN_ACTION"},
		{"enum rejects unknown value", "network.application_protocol", "TELNET", "", "must be one of"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			field, ok := udm.Lookup(test.path)
			if !ok {
				t.Fatalf("Lookup(%q) not found", test.path)
			}
			event := udm.Event{}
			err := field.Set(&event, test.value)
			if test.wantError != "" {
				if err == nil {
					t.Fatalf("Set(%q) = nil, want error containing %q", test.value, test.wantError)
				}
				if !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("Set(%q) error = %q, want it to contain %q", test.value, err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%q): %v", test.value, err)
			}
			got, ok := field.Get(&event)
			if !ok {
				t.Fatalf("%s is not set after Set", test.path)
			}
			if got != test.want {
				t.Errorf("Get = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSetPortAcceptsZero(t *testing.T) {
	field, ok := udm.Lookup("principal.port")
	if !ok {
		t.Fatal("Lookup(principal.port) not found")
	}
	if err := field.Set(&udm.Event{}, "0"); err != nil {
		t.Fatalf("Set(0): %v", err)
	}
}

func TestSetIPAppends(t *testing.T) {
	field, ok := udm.Lookup("principal.ip")
	if !ok {
		t.Fatal("Lookup(principal.ip) not found")
	}
	event := udm.Event{}
	for _, address := range []string{"203.0.113.7", "2001:db8::1"} {
		if err := field.Set(&event, address); err != nil {
			t.Fatalf("Set(%q): %v", address, err)
		}
	}
	if len(event.Principal.IP) != 2 {
		t.Fatalf("stored %d addresses, want 2", len(event.Principal.IP))
	}
	if event.Principal.IP[1] != "2001:db8::1" {
		t.Errorf("second address = %q, want 2001:db8::1", event.Principal.IP[1])
	}
	got, ok := field.Get(&event)
	if !ok || got != "203.0.113.7" {
		t.Errorf("Get = %q, %v; want the first address", got, ok)
	}
}

func TestSetValueLengthLimit(t *testing.T) {
	field, ok := udm.Lookup("metadata.description")
	if !ok {
		t.Fatal("Lookup(metadata.description) not found")
	}

	atLimit := strings.Repeat("a", 4096)
	event := udm.Event{}
	if err := field.Set(&event, atLimit); err != nil {
		t.Fatalf("Set(4096 bytes): %v", err)
	}
	got, ok := field.Get(&event)
	if !ok || got != atLimit {
		t.Errorf("Get = %d bytes, %v; want the 4096-byte value", len(got), ok)
	}

	overLimit := strings.Repeat("a", 4097)
	err := field.Set(&event, overLimit)
	if err == nil {
		t.Fatal("Set(4097 bytes) = nil, want an error")
	}
	if !strings.Contains(err.Error(), "4096") {
		t.Errorf("error = %q, want it to mention the 4096-byte limit", err)
	}
	if strings.Contains(err.Error(), overLimit) {
		t.Error("error echoes the whole oversized value")
	}
}

func TestSetErrorEchoesAtMost64Bytes(t *testing.T) {
	field, ok := udm.Lookup("principal.ip")
	if !ok {
		t.Fatal("Lookup(principal.ip) not found")
	}
	invalid := strings.Repeat("z", 100)
	err := field.Set(&udm.Event{}, invalid)
	if err == nil {
		t.Fatal("Set returned nil for an invalid IP")
	}
	if strings.Contains(err.Error(), invalid) {
		t.Error("error echoes the whole invalid value")
	}
	if len(err.Error()) > 200 {
		t.Errorf("error is %d bytes, want at most 200", len(err.Error()))
	}
}

func sampleValue(t *testing.T, field udm.Field) string {
	t.Helper()
	switch field.Kind {
	case udm.KindString:
		return "example"
	case udm.KindUserID:
		return "alice"
	case udm.KindHostname:
		return "web01.example"
	case udm.KindIP:
		return "203.0.113.7"
	case udm.KindPort:
		return "443"
	case udm.KindTimestamp:
		return "2026-05-11T10:01:00Z"
	case udm.KindEnum:
		if len(field.Values) == 0 {
			t.Fatalf("%s is an enum with no values", field.Path)
		}
		return field.Values[0]
	default:
		t.Fatalf("%s has unhandled kind %q", field.Path, field.Kind)
		return ""
	}
}

func collectLeafPaths(eventType reflect.Type, prefix string, leaves map[string]struct{}) {
	timeType := reflect.TypeOf(time.Time{})
	for index := 0; index < eventType.NumField(); index++ {
		structField := eventType.Field(index)
		if structField.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(structField.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		fieldType := structField.Type
		if fieldType == timeType || fieldType.Kind() != reflect.Struct {
			leaves[path] = struct{}{}
			continue
		}
		collectLeafPaths(fieldType, path, leaves)
	}
}
