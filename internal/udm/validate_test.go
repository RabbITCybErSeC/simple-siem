package udm_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

func TestValidateValidFailedLogon(t *testing.T) {
	if problems := udm.Validate(validFailedLogon()); len(problems) != 0 {
		t.Errorf("Validate = %v, want no errors", problems)
	}
}

func TestValidateValidGenericEvent(t *testing.T) {
	event := udm.Event{Metadata: udm.Metadata{
		EventTimestamp: time.Date(2026, time.May, 11, 10, 1, 0, 0, time.UTC),
		EventType:      udm.EventTypeGenericEvent,
	}}
	if problems := udm.Validate(event); len(problems) != 0 {
		t.Errorf("Validate = %v, want no errors", problems)
	}
}

func TestValidateValidUserLogout(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.EventType = udm.EventTypeUserLogout
	event.SecurityResult.Action = ""
	if problems := udm.Validate(event); len(problems) != 0 {
		t.Errorf("Validate = %v, want no errors", problems)
	}
}

func TestValidateRequiresEventTimestamp(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.EventTimestamp = time.Time{}
	problems := udm.Validate(event)
	if len(problems) != 1 {
		t.Fatalf("Validate = %v, want one error", problems)
	}
	if problems[0].Path != "metadata.event_timestamp" {
		t.Errorf("path = %q, want metadata.event_timestamp", problems[0].Path)
	}
}

func TestValidateRequiresEventType(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.EventType = ""
	problems := udm.Validate(event)
	if len(problems) != 1 {
		t.Fatalf("Validate = %v, want one error", problems)
	}
	if problems[0].Path != "metadata.event_type" {
		t.Errorf("path = %q, want metadata.event_type", problems[0].Path)
	}
}

func TestValidateRequiresTargetUser(t *testing.T) {
	event := validFailedLogon()
	event.Target.User.UserID = ""
	problems := udm.Validate(event)
	if !hasProblem(problems, "target.user.userid") {
		t.Errorf("Validate = %v, want an error for target.user.userid", problems)
	}
}

func TestValidateLoginRequiresHostOrIP(t *testing.T) {
	event := validFailedLogon()
	event.Target.Hostname = ""
	problems := udm.Validate(event)
	if len(problems) != 1 {
		t.Fatalf("Validate = %v, want one error", problems)
	}
	if problems[0].Path != "target.hostname" {
		t.Errorf("path = %q, want target.hostname", problems[0].Path)
	}
	if !strings.Contains(problems[0].Message, "target.ip") {
		t.Errorf("message = %q, want it to mention target.ip", problems[0].Message)
	}
}

func TestValidateLoginWithTargetIPOnly(t *testing.T) {
	event := validFailedLogon()
	event.Target.Hostname = ""
	event.Target.IP = []string{"203.0.113.7"}
	if problems := udm.Validate(event); len(problems) != 0 {
		t.Errorf("Validate = %v, want no errors", problems)
	}
}

func TestValidateLoginRequiresAction(t *testing.T) {
	event := validFailedLogon()
	event.SecurityResult.Action = ""
	problems := udm.Validate(event)
	if len(problems) != 1 {
		t.Fatalf("Validate = %v, want one error", problems)
	}
	if problems[0].Path != "security_result.action" {
		t.Errorf("path = %q, want security_result.action", problems[0].Path)
	}
}

func TestValidateRejectsInvalidEnums(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.EventType = "LOGIN"
	event.Network.ApplicationProtocol = "TELNET"
	event.Extensions.Auth.Mechanism = "PASSWORD"
	event.SecurityResult.Action = "allow"
	problems := udm.Validate(event)
	for _, path := range []string{
		"metadata.event_type",
		"network.application_protocol",
		"extensions.auth.mechanism",
		"security_result.action",
	} {
		if !hasProblem(problems, path) {
			t.Errorf("Validate = %v, want an error for %s", problems, path)
		}
	}
}

func TestValidateRejectsFieldsOutsideSubset(t *testing.T) {
	event := validFailedLogon()
	event.Principal.Application = "sshd"
	event.Principal.User.WindowsSID = "S-1-0-0"
	problems := udm.Validate(event)
	for _, path := range []string{"principal.application", "principal.user.windows_sid"} {
		if !hasProblem(problems, path) {
			t.Errorf("Validate = %v, want an error for %s", problems, path)
		}
	}
	for _, problem := range problems {
		if !strings.Contains(problem.Message, "not in the v0.1 subset") {
			t.Errorf("%s message = %q, want it to mention the v0.1 subset", problem.Path, problem.Message)
		}
	}
}

func TestValidateAcceptsTargetWindowsSID(t *testing.T) {
	event := validFailedLogon()
	event.Target.User.WindowsSID = "S-1-0-0"
	if problems := udm.Validate(event); len(problems) != 0 {
		t.Errorf("Validate = %v, want no errors", problems)
	}
}

func TestValidateRejectsInvalidIPs(t *testing.T) {
	event := validFailedLogon()
	event.Principal.IP = []string{"203.0.113.7", "not-an-ip"}
	event.Target.Hostname = ""
	event.Target.IP = []string{"fe80::1%eth0"}
	problems := udm.Validate(event)
	if !hasProblem(problems, "principal.ip") {
		t.Errorf("Validate = %v, want an error for principal.ip", problems)
	}
	if !hasProblem(problems, "target.ip") {
		t.Errorf("Validate = %v, want an error for target.ip", problems)
	}
}

func TestValidateRejectsNonCanonicalValues(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		mutate func(*udm.Event)
	}{
		{
			"uppercase user id",
			"target.user.userid",
			func(event *udm.Event) { event.Target.User.UserID = "Alice" },
		},
		{
			"untrimmed hostname",
			"target.hostname",
			func(event *udm.Event) { event.Target.Hostname = " web01" },
		},
		{
			"uppercase hostname",
			"target.hostname",
			func(event *udm.Event) { event.Target.Hostname = "WEB01" },
		},
		{
			"mapped IPv4 address",
			"target.ip",
			func(event *udm.Event) {
				event.Target.Hostname = ""
				event.Target.IP = []string{"::ffff:10.0.0.1"}
			},
		},
		{
			"uppercase IPv6 address",
			"target.ip",
			func(event *udm.Event) {
				event.Target.Hostname = ""
				event.Target.IP = []string{"2001:DB8::1"}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			event := validFailedLogon()
			test.mutate(&event)
			problems := udm.Validate(event)
			if len(problems) != 1 {
				t.Fatalf("Validate = %v, want one error", problems)
			}
			if problems[0].Path != test.path {
				t.Errorf("path = %q, want %q", problems[0].Path, test.path)
			}
			if !strings.Contains(problems[0].Message, "canonical") {
				t.Errorf("message = %q, want it to mention the canonical form", problems[0].Message)
			}
		})
	}
}

func TestValidateRejectsPortsOutOfRange(t *testing.T) {
	event := validFailedLogon()
	event.Principal.Port = -1
	event.Target.Port = 70000
	problems := udm.Validate(event)
	if !hasProblem(problems, "principal.port") {
		t.Errorf("Validate = %v, want an error for principal.port", problems)
	}
	if !hasProblem(problems, "target.port") {
		t.Errorf("Validate = %v, want an error for target.port", problems)
	}
}

func TestValidateRejectsOversizedStrings(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.Description = strings.Repeat("a", 5000)
	event.Target.Application = strings.Repeat("b", 5000)
	problems := udm.Validate(event)
	if !hasProblem(problems, "metadata.description") {
		t.Errorf("Validate = %v, want an error for metadata.description", problems)
	}
	if !hasProblem(problems, "target.application") {
		t.Errorf("Validate = %v, want an error for target.application", problems)
	}
}

func TestValidateRejectsAdditionalKeys(t *testing.T) {
	event := validFailedLogon()
	event.Additional = map[string]string{
		"Bad-Key":    "value",
		"good_key":   strings.Repeat("v", 5000),
		"source_geo": "US",
	}
	problems := udm.Validate(event)
	if !hasProblem(problems, "additional.Bad-Key") {
		t.Errorf("Validate = %v, want an error for additional.Bad-Key", problems)
	}
	if !hasProblem(problems, "additional.good_key") {
		t.Errorf("Validate = %v, want an error for the oversized additional.good_key", problems)
	}
	if hasProblem(problems, "additional.source_geo") {
		t.Errorf("Validate = %v, want no error for additional.source_geo", problems)
	}
}

func TestValidateSortsErrorsByPath(t *testing.T) {
	event := validFailedLogon()
	event.Metadata.EventTimestamp = time.Time{}
	event.Target.User.UserID = ""
	event.Target.Hostname = ""
	event.SecurityResult.Action = "allow"
	problems := udm.Validate(event)
	if len(problems) < 2 {
		t.Fatalf("Validate = %v, want several errors", problems)
	}
	paths := make([]string, len(problems))
	for index, problem := range problems {
		paths[index] = problem.Path
	}
	want := []string{
		"metadata.event_timestamp",
		"security_result.action",
		"target.hostname",
		"target.user.userid",
	}
	if !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestValidationErrorString(t *testing.T) {
	problem := udm.ValidationError{Path: "metadata.description", Message: "is required"}
	if got, want := problem.Error(), "metadata.description: is required"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func validFailedLogon() udm.Event {
	return udm.Event{
		Metadata: udm.Metadata{
			EventTimestamp: time.Date(2026, time.May, 11, 10, 1, 0, 0, time.UTC),
			EventType:      udm.EventTypeUserLogin,
		},
		Target: udm.Noun{
			Hostname: "web01",
			User:     udm.User{UserID: "alice"},
		},
		SecurityResult: udm.SecurityResult{Action: udm.ActionBlock},
	}
}

func hasProblem(problems []udm.ValidationError, path string) bool {
	for _, problem := range problems {
		if problem.Path == path {
			return true
		}
	}
	return false
}
