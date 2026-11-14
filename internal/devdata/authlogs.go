package devdata

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"time"
)

const (
	datasetWindow = 2 * time.Hour

	timestampLayout = "2006-01-02T15:04:05.000Z"
	indexDayLayout  = "2006.01.02"

	ingestJitterSeconds = 20
	windowsRecordIDBase = 918273
)

const (
	linuxSource        = "linux"
	windowsSource      = "windows"
	scenarioBackground = "background"
)

var (
	backgroundUsers   = []string{"alice", "bob", "carol", "dave", "erin", "svc-backup"}
	linuxHosts        = []string{"web01", "web02", "bastion01"}
	windowsHosts      = []string{"dc01", "ws-finance-01"}
	windowsLogonTypes = []string{"2", "3", "10"}
)

var windowsLogonTypeNames = map[string]string{
	"2":  "Interactive",
	"3":  "Network",
	"10": "RemoteInteractive",
}

// GenerateAuthLogs returns the synthetic sshd and Windows logon dataset
// described by the dev-elasticsearch-data design.
func GenerateAuthLogs(options Options) []Document {
	generator := &generator{
		options: options,
		end:     options.End.UTC(),
		// Scenario details must not depend on Seed: a different seed changes
		// only background documents, so scenario assertions stay stable.
		scenarioRand:   rand.New(rand.NewPCG(0, 0)),
		backgroundRand: rand.New(rand.NewPCG(uint64(options.Seed), 0)),
	}

	generator.addScenarios()
	generator.addBackground()
	slices.SortFunc(generator.documents, func(left, right Document) int {
		if order := cmp.Compare(left.Source["@timestamp"].(string), right.Source["@timestamp"].(string)); order != 0 {
			return order
		}
		return cmp.Compare(left.ID, right.ID)
	})
	return generator.documents
}

func (generator *generator) addScenarios() {
	generator.addLinuxSequence("linux-burst-then-success", "alice", "web01",
		"203.0.113.7", "203.0.113.7", generator.end.Add(-40*time.Minute), 15*time.Second, 12, 30*time.Second)
	generator.addWindowsSequence("windows-burst-then-success", "bob", "dc01",
		"203.0.113.20", generator.end.Add(-25*time.Minute), 10*time.Second, 12, 20*time.Second)
	generator.addLinuxSequence("near-miss", "carol", "web02",
		"198.51.100.14", "198.51.100.14", generator.end.Add(-60*time.Minute), 20*time.Second, 5, 30*time.Second)
	generator.addLinuxSequence("failures-only", "dave", "bastion01",
		"203.0.113.99", "", generator.end.Add(-90*time.Minute), 5*time.Second, 15, 0)
	generator.addLinuxSequence("other-origin-success", "erin", "web01",
		"203.0.113.50", "198.51.100.77", generator.end.Add(-75*time.Minute), 10*time.Second, 12, 30*time.Second)
	generator.addLinuxEvent(generator.scenarioRand, "malformed-no-user", generator.end.Add(-10*time.Minute), "", "web02", "203.0.113.8", false)
}

// addLinuxSequence writes one burst of sshd failures and, when successOrigin
// is set, a success after the burst.
func (generator *generator) addLinuxSequence(scenario, user, host, failureOrigin, successOrigin string, start time.Time, spacing time.Duration, failures int, successDelay time.Duration) {
	last := start
	for index := 0; index < failures; index++ {
		last = start.Add(time.Duration(index) * spacing)
		generator.addLinuxEvent(generator.scenarioRand, scenario, last, user, host, failureOrigin, false)
	}
	if successOrigin != "" {
		generator.addLinuxEvent(generator.scenarioRand, scenario, last.Add(successDelay), user, host, successOrigin, true)
	}
}

func (generator *generator) addWindowsSequence(scenario, user, host, origin string, start time.Time, spacing time.Duration, failures int, successDelay time.Duration) {
	last := start
	for index := 0; index < failures; index++ {
		last = start.Add(time.Duration(index) * spacing)
		generator.addWindowsEvent(generator.scenarioRand, scenario, last, user, host, origin, "3", false)
	}
	generator.addWindowsEvent(generator.scenarioRand, scenario, last.Add(successDelay), user, host, origin, "3", true)
}

func (generator *generator) addBackground() {
	if generator.options.Background <= 0 {
		return
	}

	window := int64(datasetWindow / time.Millisecond)
	start := generator.end.Add(-datasetWindow)
	failuresByKey := map[string]int{}

	for index := 0; index < generator.options.Background; index++ {
		at := start.Add(time.Duration(generator.backgroundRand.Int64N(window)) * time.Millisecond)
		user := backgroundUsers[generator.backgroundRand.IntN(len(backgroundUsers))]
		origin := fmt.Sprintf("10.20.0.%d", 2+generator.backgroundRand.IntN(253))

		if generator.backgroundRand.IntN(2) == 0 {
			host := linuxHosts[generator.backgroundRand.IntN(len(linuxHosts))]
			success := generator.backgroundSuccess(failuresByKey, user, host, origin)
			generator.addLinuxEvent(generator.backgroundRand, scenarioBackground, at, user, host, origin, success)
			continue
		}

		host := windowsHosts[generator.backgroundRand.IntN(len(windowsHosts))]
		success := generator.backgroundSuccess(failuresByKey, user, host, origin)
		logonType := windowsLogonTypes[generator.backgroundRand.IntN(len(windowsLogonTypes))]
		generator.addWindowsEvent(generator.backgroundRand, scenarioBackground, at, user, host, origin, logonType, success)
	}
}

// backgroundSuccess keeps every (user, host, origin) at two failures or fewer
// by turning a third failure into a success.
func (generator *generator) backgroundSuccess(failuresByKey map[string]int, user, host, origin string) bool {
	if generator.backgroundRand.IntN(100) < 85 {
		return true
	}
	key := user + "|" + host + "|" + origin
	if failuresByKey[key] >= 2 {
		return true
	}
	failuresByKey[key]++
	return false
}

func (generator *generator) addLinuxEvent(random *rand.Rand, scenario string, at time.Time, user, host, origin string, success bool) {
	port := 40000 + random.IntN(25000)
	pid := 1000 + random.IntN(64000)
	ingested := at.Add(time.Duration(1+random.IntN(ingestJitterSeconds)) * time.Second)

	eventType := []string{"info"}
	outcome := "failure"
	sshEvent := "Failed"
	message := fmt.Sprintf("Failed password for %s from %s port %d ssh2", user, origin, port)
	if user == "" {
		message = fmt.Sprintf("Failed password for invalid user from %s port %d ssh2", origin, port)
	}
	if success {
		eventType = []string{"start"}
		outcome = "success"
		sshEvent = "Accepted"
		message = fmt.Sprintf("Accepted password for %s from %s port %d ssh2", user, origin, port)
	}

	source := map[string]any{
		"@timestamp": formatTimestamp(at),
		"event": map[string]any{
			"category": []string{"authentication"},
			"type":     eventType,
			"action":   "ssh_login",
			"outcome":  outcome,
			"ingested": formatTimestamp(ingested),
			"dataset":  "system.auth",
			"module":   "system",
			"kind":     "event",
		},
		"process": map[string]any{"name": "sshd", "pid": pid},
		"host": map[string]any{
			"name":     host,
			"hostname": host,
			"os":       map[string]any{"type": "linux"},
		},
		"source": map[string]any{"ip": origin, "port": port},
		"system": map[string]any{
			"auth": map[string]any{
				"ssh": map[string]any{"event": sshEvent, "method": "password"},
			},
		},
		"message": message,
	}
	if user != "" {
		source["user"] = map[string]any{"name": user}
		source["related"] = map[string]any{"user": []string{user}, "ip": []string{origin}}
	} else {
		source["related"] = map[string]any{"ip": []string{origin}}
	}

	generator.append(scenario, at, linuxSource, source)
}

func (generator *generator) addWindowsEvent(random *rand.Rand, scenario string, at time.Time, user, host, origin, logonType string, success bool) {
	port := 40000 + random.IntN(25000)
	ingested := at.Add(time.Duration(1+random.IntN(ingestJitterSeconds)) * time.Second)

	eventID := "4625"
	action := "logon-failed"
	outcome := "failure"
	message := "An account failed to log on."
	sid := "S-1-0-0"
	subStatus := "0xc000006a"
	logon := map[string]any{
		"type":    windowsLogonTypeNames[logonType],
		"failure": map[string]any{"reason": "Unknown user name or bad password."},
	}
	if success {
		eventID = "4624"
		action = "logged-in"
		outcome = "success"
		message = "An account was successfully logged on."
		sid = "S-1-5-21-1000-1000-1000-1104"
		subStatus = "0x0"
		logon = map[string]any{"type": windowsLogonTypeNames[logonType]}
	}

	source := map[string]any{
		"@timestamp": formatTimestamp(at),
		"event": map[string]any{
			"category": []string{"authentication"},
			"type":     []string{"start"},
			"code":     eventID,
			"action":   action,
			"outcome":  outcome,
			"ingested": formatTimestamp(ingested),
			"provider": "Microsoft-Windows-Security-Auditing",
			"module":   "security",
			"kind":     "event",
		},
		"host": map[string]any{
			"name":     host,
			"hostname": host,
			"os":       map[string]any{"type": "windows"},
		},
		"user":   map[string]any{"name": user, "domain": "CORP"},
		"source": map[string]any{"ip": origin, "port": port},
		"winlog": map[string]any{
			"channel":       "Security",
			"event_id":      eventID,
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"computer_name": host + ".corp.example",
			"event_data": map[string]any{
				"TargetUserName":   user,
				"TargetDomainName": "CORP",
				"TargetUserSid":    sid,
				"LogonType":        logonType,
				"IpAddress":        origin,
				"IpPort":           strconv.Itoa(port),
				"WorkstationName":  "-",
				"SubStatus":        subStatus,
			},
			"logon": logon,
		},
		"message": message,
	}

	generator.append(scenario, at, windowsSource, source)
}

func (generator *generator) append(scenario string, at time.Time, sourceType string, source map[string]any) {
	if sourceType == windowsSource {
		// Number in generation order, so scenario record ids do not shift when
		// a different seed interleaves background events.
		source["winlog"].(map[string]any)["record_id"] = windowsRecordIDBase + generator.windowsRecordID
		generator.windowsRecordID++
	}

	generator.sequence++
	generator.documents = append(generator.documents, Document{
		Index:    generator.indexName(sourceType, at),
		ID:       documentID(generator.options.IndexPrefix, generator.options.Seed, generator.sequence),
		Scenario: scenario,
		Source:   source,
	})
}

func (generator *generator) indexName(sourceType string, at time.Time) string {
	return fmt.Sprintf("%s-%s-%s", generator.options.IndexPrefix, sourceType, at.UTC().Format(indexDayLayout))
}

func formatTimestamp(at time.Time) string {
	return at.UTC().Format(timestampLayout)
}

func documentID(prefix string, seed int64, sequence int) string {
	input := fmt.Sprintf("%s|%d|%d", prefix, seed, sequence)
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:20]
}
