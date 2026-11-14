package devdata_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
)

const scenarioBackground = "background"

var (
	scenarioNames = []string{
		"linux-burst-then-success",
		"windows-burst-then-success",
		"near-miss",
		"failures-only",
		"other-origin-success",
		"malformed-no-user",
	}
	backgroundUsers = []string{"alice", "bob", "carol", "dave", "erin", "svc-backup"}
	linuxHosts      = []string{"web01", "web02", "bastion01"}
	windowsHosts    = []string{"dc01", "ws-finance-01"}

	backgroundNetwork = netip.MustParsePrefix("10.20.0.0/24")
)

func authLogOptions() devdata.Options {
	return devdata.Options{
		Seed:        1,
		End:         time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC),
		IndexPrefix: "auth",
		Background:  200,
	}
}

func TestGenerateAuthLogsIsDeterministic(t *testing.T) {
	options := authLogOptions()

	first, err := json.Marshal(devdata.GenerateAuthLogs(options))
	if err != nil {
		t.Fatalf("marshal first dataset: %v", err)
	}
	second, err := json.Marshal(devdata.GenerateAuthLogs(options))
	if err != nil {
		t.Fatalf("marshal second dataset: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("the same options produced different JSON")
	}
}

// Document ids deliberately include the seed, so a different seed changes
// every id; the scenario sources must still not change.
func TestGenerateAuthLogsAnotherSeedChangesOnlyBackground(t *testing.T) {
	firstOptions := authLogOptions()
	secondOptions := authLogOptions()
	secondOptions.Seed = 2

	first := devdata.GenerateAuthLogs(firstOptions)
	second := devdata.GenerateAuthLogs(secondOptions)

	for _, scenario := range scenarioNames {
		firstDocuments := scenarioDocuments(first, scenario)
		secondDocuments := scenarioDocuments(second, scenario)
		if len(firstDocuments) != len(secondDocuments) {
			t.Fatalf("scenario %s has %d documents with seed 1 and %d with seed 2",
				scenario, len(firstDocuments), len(secondDocuments))
		}
		for index := range firstDocuments {
			firstSource, err := json.Marshal(firstDocuments[index].Source)
			if err != nil {
				t.Fatalf("marshal %s source: %v", scenario, err)
			}
			secondSource, err := json.Marshal(secondDocuments[index].Source)
			if err != nil {
				t.Fatalf("marshal %s source: %v", scenario, err)
			}
			if !bytes.Equal(firstSource, secondSource) {
				t.Errorf("scenario %s document %d changed with the seed", scenario, index)
			}
		}
	}

	firstBackground := scenarioDocuments(first, scenarioBackground)
	secondBackground := scenarioDocuments(second, scenarioBackground)
	changed := false
	for index := range firstBackground {
		firstSource, err := json.Marshal(firstBackground[index].Source)
		if err != nil {
			t.Fatalf("marshal background source: %v", err)
		}
		secondSource, err := json.Marshal(secondBackground[index].Source)
		if err != nil {
			t.Fatalf("marshal background source: %v", err)
		}
		if !bytes.Equal(firstSource, secondSource) {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("background did not change with the seed")
	}
}

func TestGenerateAuthLogsScenarios(t *testing.T) {
	end := authLogOptions().End
	documents := devdata.GenerateAuthLogs(authLogOptions())

	expectations := []struct {
		scenario      string
		count         int
		first         time.Time
		spacing       time.Duration
		failures      int
		successDelay  time.Duration
		failureOrigin string
		successOrigin string
		user          string
		host          string
		windows       bool
	}{
		{"linux-burst-then-success", 13, end.Add(-40 * time.Minute), 15 * time.Second, 12, 30 * time.Second, "203.0.113.7", "203.0.113.7", "alice", "web01", false},
		{"windows-burst-then-success", 13, end.Add(-25 * time.Minute), 10 * time.Second, 12, 20 * time.Second, "203.0.113.20", "203.0.113.20", "bob", "dc01", true},
		{"near-miss", 6, end.Add(-60 * time.Minute), 20 * time.Second, 5, 30 * time.Second, "198.51.100.14", "198.51.100.14", "carol", "web02", false},
		{"failures-only", 15, end.Add(-90 * time.Minute), 5 * time.Second, 15, 0, "203.0.113.99", "", "dave", "bastion01", false},
		{"other-origin-success", 13, end.Add(-75 * time.Minute), 10 * time.Second, 12, 30 * time.Second, "203.0.113.50", "198.51.100.77", "erin", "web01", false},
		{"malformed-no-user", 1, end.Add(-10 * time.Minute), 0, 1, 0, "203.0.113.8", "", "", "web02", false},
	}

	for _, expectation := range expectations {
		t.Run(expectation.scenario, func(t *testing.T) {
			documents := scenarioDocuments(documents, expectation.scenario)
			if len(documents) != expectation.count {
				t.Fatalf("documents = %d, want %d", len(documents), expectation.count)
			}

			for index := 0; index < expectation.failures; index++ {
				document := documents[index]
				want := expectation.first.Add(time.Duration(index) * expectation.spacing)
				if got := timestampOf(t, document); !got.Equal(want) {
					t.Errorf("failure %d at %s, want %s", index, got, want)
				}
				if got := stringAt(t, document.Source, "event", "outcome"); got != "failure" {
					t.Errorf("failure %d outcome = %q, want failure", index, got)
				}
				if got := stringAt(t, document.Source, "source", "ip"); got != expectation.failureOrigin {
					t.Errorf("failure %d origin = %q, want %q", index, got, expectation.failureOrigin)
				}
				if got := stringAt(t, document.Source, "host", "name"); got != expectation.host {
					t.Errorf("failure %d host = %q, want %q", index, got, expectation.host)
				}
				if expectation.windows {
					if got := stringAt(t, document.Source, "event", "code"); got != "4625" {
						t.Errorf("failure %d event.code = %q, want 4625", index, got)
					}
					if got := stringAt(t, document.Source, "winlog", "event_id"); got != "4625" {
						t.Errorf("failure %d winlog.event_id = %q, want 4625", index, got)
					}
					if got := stringAt(t, document.Source, "event", "action"); got != "logon-failed" {
						t.Errorf("failure %d event.action = %q, want logon-failed", index, got)
					}
					if got := stringAt(t, document.Source, "winlog", "event_data", "LogonType"); got != "3" {
						t.Errorf("failure %d LogonType = %q, want 3", index, got)
					}
					if got := stringAt(t, document.Source, "winlog", "logon", "type"); got != "Network" {
						t.Errorf("failure %d logon.type = %q, want Network", index, got)
					}
					if got := stringAt(t, document.Source, "winlog", "event_data", "TargetUserName"); got != expectation.user {
						t.Errorf("failure %d TargetUserName = %q, want %q", index, got, expectation.user)
					}
					if got := stringAt(t, document.Source, "winlog", "event_data", "IpAddress"); got != expectation.failureOrigin {
						t.Errorf("failure %d IpAddress = %q, want %q", index, got, expectation.failureOrigin)
					}
				} else {
					if got := stringAt(t, document.Source, "system", "auth", "ssh", "event"); got != "Failed" {
						t.Errorf("failure %d ssh event = %q, want Failed", index, got)
					}
					if got := stringAt(t, document.Source, "process", "name"); got != "sshd" {
						t.Errorf("failure %d process.name = %q, want sshd", index, got)
					}
					if got := stringsAt(t, document.Source, "related", "ip"); !slices.Equal(got, []string{expectation.failureOrigin}) {
						t.Errorf("failure %d related.ip = %v, want [%s]", index, got, expectation.failureOrigin)
					}
					if expectation.user != "" {
						if got := stringsAt(t, document.Source, "related", "user"); !slices.Equal(got, []string{expectation.user}) {
							t.Errorf("failure %d related.user = %v, want [%s]", index, got, expectation.user)
						}
					}
				}
				if expectation.user != "" {
					if got := stringAt(t, document.Source, "user", "name"); got != expectation.user {
						t.Errorf("failure %d user = %q, want %q", index, got, expectation.user)
					}
				}
			}

			if expectation.successOrigin == "" {
				return
			}
			document := documents[expectation.failures]
			want := expectation.first.Add(time.Duration(expectation.failures-1)*expectation.spacing + expectation.successDelay)
			if got := timestampOf(t, document); !got.Equal(want) {
				t.Errorf("success at %s, want %s", got, want)
			}
			if got := stringAt(t, document.Source, "event", "outcome"); got != "success" {
				t.Errorf("success outcome = %q, want success", got)
			}
			if got := stringAt(t, document.Source, "source", "ip"); got != expectation.successOrigin {
				t.Errorf("success origin = %q, want %q", got, expectation.successOrigin)
			}
			if got := stringAt(t, document.Source, "user", "name"); got != expectation.user {
				t.Errorf("success user = %q, want %q", got, expectation.user)
			}
			if expectation.windows {
				if got := stringAt(t, document.Source, "event", "code"); got != "4624" {
					t.Errorf("success event.code = %q, want 4624", got)
				}
				if got := stringAt(t, document.Source, "winlog", "event_id"); got != "4624" {
					t.Errorf("success winlog.event_id = %q, want 4624", got)
				}
				if got := stringAt(t, document.Source, "event", "action"); got != "logged-in" {
					t.Errorf("success event.action = %q, want logged-in", got)
				}
				if got := stringAt(t, document.Source, "winlog", "logon", "type"); got != "Network" {
					t.Errorf("success logon.type = %q, want Network", got)
				}
				if got := stringAt(t, document.Source, "winlog", "event_data", "LogonType"); got != "3" {
					t.Errorf("success LogonType = %q, want 3", got)
				}
				if got := stringAt(t, document.Source, "winlog", "event_data", "IpAddress"); got != expectation.successOrigin {
					t.Errorf("success IpAddress = %q, want %q", got, expectation.successOrigin)
				}
				winlog := document.Source["winlog"].(map[string]any)
				logon := winlog["logon"].(map[string]any)
				if _, ok := logon["failure"]; ok {
					t.Error("success carries winlog.logon.failure")
				}
				if sid := stringAt(t, document.Source, "winlog", "event_data", "TargetUserSid"); !strings.HasPrefix(sid, "S-1-5-21-") {
					t.Errorf("success TargetUserSid = %q, want a domain SID", sid)
				}
			} else {
				if got := stringsAt(t, document.Source, "event", "type"); !slices.Equal(got, []string{"start"}) {
					t.Errorf("success event.type = %v, want [start]", got)
				}
				if got := stringAt(t, document.Source, "system", "auth", "ssh", "event"); got != "Accepted" {
					t.Errorf("success ssh event = %q, want Accepted", got)
				}
				if got := stringsAt(t, document.Source, "related", "user"); !slices.Equal(got, []string{expectation.user}) {
					t.Errorf("success related.user = %v, want [%s]", got, expectation.user)
				}
				if got := stringsAt(t, document.Source, "related", "ip"); !slices.Equal(got, []string{expectation.successOrigin}) {
					t.Errorf("success related.ip = %v, want [%s]", got, expectation.successOrigin)
				}
				message := stringAt(t, document.Source, "message")
				wantMessage := fmt.Sprintf("Accepted password for %s from %s", expectation.user, expectation.successOrigin)
				if !strings.Contains(message, wantMessage) {
					t.Errorf("success message = %q, want it to contain %q", message, wantMessage)
				}
			}
		})
	}
}

func TestGenerateAuthLogsMalformedDocumentHasNoUser(t *testing.T) {
	documents := devdata.GenerateAuthLogs(authLogOptions())
	malformed := scenarioDocuments(documents, "malformed-no-user")
	if len(malformed) != 1 {
		t.Fatalf("malformed documents = %d, want 1", len(malformed))
	}
	document := malformed[0]

	if _, ok := document.Source["user"]; ok {
		t.Error("malformed document carries user.name")
	}
	related := document.Source["related"].(map[string]any)
	if _, ok := related["user"]; ok {
		t.Error("malformed document carries related.user")
	}
	if message := stringAt(t, document.Source, "message"); !strings.Contains(message, "invalid user") {
		t.Errorf("message = %q, want an invalid-user message", message)
	}
}

func TestGenerateAuthLogsWindowsRecordIDs(t *testing.T) {
	documents := devdata.GenerateAuthLogs(authLogOptions())

	seen := map[int]bool{}
	for _, document := range documents {
		if _, ok := document.Source["winlog"]; !ok {
			continue
		}
		recordID := intAt(t, document.Source, "winlog", "record_id")
		if recordID < 918273 {
			t.Errorf("record_id = %d, want at least 918273", recordID)
		}
		if seen[recordID] {
			t.Errorf("duplicate record_id %d", recordID)
		}
		seen[recordID] = true
	}

	scenario := scenarioDocuments(documents, "windows-burst-then-success")
	for index := 1; index < len(scenario); index++ {
		previous := intAt(t, scenario[index-1].Source, "winlog", "record_id")
		current := intAt(t, scenario[index].Source, "winlog", "record_id")
		if current != previous+1 {
			t.Errorf("scenario record_id %d follows %d, want consecutive ids", current, previous)
		}
	}
}

func TestGenerateAuthLogsBackgroundBounds(t *testing.T) {
	for _, seed := range []int64{1, 2, 3, 42, 1234} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			options := authLogOptions()
			options.Seed = seed
			documents := scenarioDocuments(devdata.GenerateAuthLogs(options), scenarioBackground)
			if len(documents) != options.Background {
				t.Fatalf("background documents = %d, want %d", len(documents), options.Background)
			}

			failuresByKey := map[string]int{}
			successes := 0
			sources := map[string]bool{}
			for _, document := range documents {
				user := stringAt(t, document.Source, "user", "name")
				if !slices.Contains(backgroundUsers, user) {
					t.Errorf("background user = %q, want one of %v", user, backgroundUsers)
				}
				host := stringAt(t, document.Source, "host", "name")
				origin := stringAt(t, document.Source, "source", "ip")
				address, err := netip.ParseAddr(origin)
				if err != nil || !backgroundNetwork.Contains(address) {
					t.Errorf("background origin = %q, want an address in %s", origin, backgroundNetwork)
				}

				source := stringAt(t, document.Source, "host", "os", "type")
				sources[source] = true
				switch source {
				case "linux":
					if !slices.Contains(linuxHosts, host) {
						t.Errorf("linux background host = %q, want one of %v", host, linuxHosts)
					}
				case "windows":
					if !slices.Contains(windowsHosts, host) {
						t.Errorf("windows background host = %q, want one of %v", host, windowsHosts)
					}
					logonType := stringAt(t, document.Source, "winlog", "event_data", "LogonType")
					logonName := map[string]string{"2": "Interactive", "3": "Network", "10": "RemoteInteractive"}[logonType]
					if logonName == "" {
						t.Errorf("windows background LogonType = %q, want 2, 3, or 10", logonType)
					} else if got := stringAt(t, document.Source, "winlog", "logon", "type"); got != logonName {
						t.Errorf("LogonType %s has winlog.logon.type %q, want %q", logonType, got, logonName)
					}
				default:
					t.Errorf("background host.os.type = %q, want linux or windows", source)
				}

				switch outcome := stringAt(t, document.Source, "event", "outcome"); outcome {
				case "success":
					successes++
				case "failure":
					failuresByKey[user+"|"+host+"|"+origin]++
				default:
					t.Errorf("background outcome = %q, want success or failure", outcome)
				}
			}

			for key, failures := range failuresByKey {
				if failures > 2 {
					t.Errorf("%s has %d failures, want at most 2", key, failures)
				}
			}
			successRatio := float64(successes) / float64(len(documents))
			if successRatio < 0.75 || successRatio > 0.95 {
				t.Errorf("success ratio = %.2f, want about 0.85", successRatio)
			}
			if !sources["linux"] || !sources["windows"] {
				t.Errorf("background sources = %v, want both linux and windows", sources)
			}
		})
	}
}

func TestGenerateAuthLogsTimesAndIndices(t *testing.T) {
	options := authLogOptions()
	documents := devdata.GenerateAuthLogs(options)
	windowStart := options.End.Add(-2 * time.Hour)

	for _, document := range documents {
		at := timestampOf(t, document)
		if at.Before(windowStart) || !at.Before(options.End) {
			t.Errorf("timestamp %s outside [%s, %s)", at, windowStart, options.End)
		}

		ingested, err := time.Parse(time.RFC3339Nano, stringAt(t, document.Source, "event", "ingested"))
		if err != nil {
			t.Fatalf("parse event.ingested: %v", err)
		}
		if jitter := ingested.Sub(at); jitter < time.Second || jitter > 20*time.Second {
			t.Errorf("event.ingested is %s after @timestamp, want 1-20s", jitter)
		}

		source := stringAt(t, document.Source, "host", "os", "type")
		wantIndex := fmt.Sprintf("%s-%s-%s", options.IndexPrefix, source, at.UTC().Format("2006.01.02"))
		if document.Index != wantIndex {
			t.Errorf("index = %q, want %q", document.Index, wantIndex)
		}
	}
}

// The malformed event sits ten minutes before an end just after midnight,
// while the other sshd scenarios are on the previous day.
func TestGenerateAuthLogsSplitsAtMidnight(t *testing.T) {
	options := authLogOptions()
	options.End = time.Date(2026, time.November, 13, 0, 30, 0, 0, time.UTC)

	indices := map[string]bool{}
	for _, document := range devdata.GenerateAuthLogs(options) {
		if stringAt(t, document.Source, "host", "os", "type") == "linux" {
			indices[document.Index] = true
		}
	}
	if len(indices) != 2 {
		t.Errorf("linux indices = %v, want documents on both sides of midnight", indices)
	}
}

func TestGenerateAuthLogsSortedWithOpaqueIDs(t *testing.T) {
	documents := devdata.GenerateAuthLogs(authLogOptions())

	seen := map[string]bool{}
	for index, document := range documents {
		if len(document.ID) != 20 {
			t.Errorf("id %q has %d characters, want 20", document.ID, len(document.ID))
		}
		if _, err := hex.DecodeString(document.ID); err != nil {
			t.Errorf("id %q is not hex: %v", document.ID, err)
		}
		if seen[document.ID] {
			t.Errorf("duplicate id %q", document.ID)
		}
		seen[document.ID] = true

		if index == 0 {
			continue
		}
		previous := documents[index-1]
		previousTimestamp := stringAt(t, previous.Source, "@timestamp")
		currentTimestamp := stringAt(t, document.Source, "@timestamp")
		if previousTimestamp > currentTimestamp ||
			(previousTimestamp == currentTimestamp && previous.ID > document.ID) {
			t.Errorf("document %d (%s, %s) sorts before its predecessor (%s, %s)",
				index, currentTimestamp, document.ID, previousTimestamp, previous.ID)
		}
	}
}

func TestGenerateAuthLogsIDsDoNotDependOnEnd(t *testing.T) {
	firstOptions := authLogOptions()
	secondOptions := authLogOptions()
	secondOptions.End = firstOptions.End.Add(8 * time.Hour)

	first := documentIDs(devdata.GenerateAuthLogs(firstOptions))
	second := documentIDs(devdata.GenerateAuthLogs(secondOptions))
	if !slices.Equal(first, second) {
		t.Error("ids changed when only --end changed")
	}

	otherSeedOptions := authLogOptions()
	otherSeedOptions.Seed = 2
	if slices.Equal(first, documentIDs(devdata.GenerateAuthLogs(otherSeedOptions))) {
		t.Error("ids did not change with the seed")
	}

	otherPrefixOptions := authLogOptions()
	otherPrefixOptions.IndexPrefix = "other"
	if slices.Equal(first, documentIDs(devdata.GenerateAuthLogs(otherPrefixOptions))) {
		t.Error("ids did not change with the prefix")
	}
}

func documentIDs(documents []devdata.Document) []string {
	ids := make([]string, len(documents))
	for index, document := range documents {
		ids[index] = document.ID
	}
	return ids
}

func scenarioDocuments(documents []devdata.Document, scenario string) []devdata.Document {
	var matching []devdata.Document
	for _, document := range documents {
		if document.Scenario == scenario {
			matching = append(matching, document)
		}
	}
	return matching
}

func timestampOf(t *testing.T, document devdata.Document) time.Time {
	t.Helper()
	timestamp, err := time.Parse(time.RFC3339Nano, stringAt(t, document.Source, "@timestamp"))
	if err != nil {
		t.Fatalf("parse @timestamp: %v", err)
	}
	return timestamp
}

func stringAt(t *testing.T, object map[string]any, path ...string) string {
	t.Helper()
	value := valueAt(t, object, path...)
	text, ok := value.(string)
	if !ok {
		t.Fatalf("%s is %T, want string", strings.Join(path, "."), value)
	}
	return text
}

func stringsAt(t *testing.T, object map[string]any, path ...string) []string {
	t.Helper()
	value := valueAt(t, object, path...)
	values, ok := value.([]string)
	if !ok {
		t.Fatalf("%s is %T, want []string", strings.Join(path, "."), value)
	}
	return values
}

func intAt(t *testing.T, object map[string]any, path ...string) int {
	t.Helper()
	value := valueAt(t, object, path...)
	number, ok := value.(int)
	if !ok {
		t.Fatalf("%s is %T, want int", strings.Join(path, "."), value)
	}
	return number
}

func valueAt(t *testing.T, object map[string]any, path ...string) any {
	t.Helper()
	var current any = object
	for position, key := range path {
		currentObject, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("%s is %T, want an object", strings.Join(path[:position], "."), current)
		}
		current, ok = currentObject[key]
		if !ok {
			t.Fatalf("%s is missing", strings.Join(path[:position+1], "."))
		}
	}
	return current
}
