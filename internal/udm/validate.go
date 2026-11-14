package udm

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Validate reports every problem in event, sorted by path.
func Validate(event Event) []ValidationError {
	var problems []ValidationError

	if event.Metadata.EventTimestamp.IsZero() {
		problems = append(problems, ValidationError{Path: "metadata.event_timestamp", Message: "is required"})
	}
	switch {
	case event.Metadata.EventType == "":
		problems = append(problems, ValidationError{Path: "metadata.event_type", Message: "is required"})
	case !event.Metadata.EventType.Valid():
		problems = append(problems, ValidationError{
			Path:    "metadata.event_type",
			Message: enumExpectation(eventTypeValues, string(event.Metadata.EventType)),
		})
	}

	for _, field := range []struct {
		path   string
		value  string
		values []string
	}{
		{"network.application_protocol", string(event.Network.ApplicationProtocol), applicationProtocolValues},
		{"extensions.auth.mechanism", string(event.Extensions.Auth.Mechanism), authMechanismValues},
		{"security_result.action", string(event.SecurityResult.Action), actionValues},
	} {
		if field.value != "" && !slices.Contains(field.values, field.value) {
			problems = append(problems, ValidationError{
				Path:    field.path,
				Message: enumExpectation(field.values, field.value),
			})
		}
	}

	switch event.Metadata.EventType {
	case EventTypeUserLogin, EventTypeUserLogout:
		if event.Target.User.UserID == "" {
			problems = append(problems, ValidationError{Path: "target.user.userid", Message: "is required"})
		}
		if event.Target.Hostname == "" && len(event.Target.IP) == 0 {
			problems = append(problems, ValidationError{
				Path:    "target.hostname",
				Message: "one of target.hostname, target.ip is required",
			})
		}
		if event.Metadata.EventType == EventTypeUserLogin && event.SecurityResult.Action == "" {
			problems = append(problems, ValidationError{Path: "security_result.action", Message: "is required"})
		}
	}

	if event.Principal.Application != "" {
		problems = append(problems, ValidationError{
			Path:    "principal.application",
			Message: "field not in the v0.1 subset",
		})
	}
	if event.Principal.User.WindowsSID != "" {
		problems = append(problems, ValidationError{
			Path:    "principal.user.windows_sid",
			Message: "field not in the v0.1 subset",
		})
	}

	problems = append(problems, invalidIPs("principal.ip", event.Principal.IP)...)
	problems = append(problems, invalidIPs("target.ip", event.Target.IP)...)

	if event.Principal.Port < 0 || event.Principal.Port > 65535 {
		problems = append(problems, ValidationError{
			Path:    "principal.port",
			Message: "must be a port number between 0 and 65535",
		})
	}
	if event.Target.Port < 0 || event.Target.Port > 65535 {
		problems = append(problems, ValidationError{
			Path:    "target.port",
			Message: "must be a port number between 0 and 65535",
		})
	}

	for _, field := range catalog {
		switch field.Kind {
		case KindString, KindUserID, KindHostname:
			value, ok := field.Get(&event)
			if ok && len(value) > maxValueBytes {
				problems = append(problems, ValidationError{
					Path:    field.Path,
					Message: fmt.Sprintf("value is longer than %d bytes", maxValueBytes),
				})
			}
		}
	}

	for key, value := range event.Additional {
		path := "additional." + key
		if !additionalKeyPattern.MatchString(key) {
			problems = append(problems, ValidationError{
				Path:    path,
				Message: "must match " + additionalKeyPattern.String(),
			})
		}
		if len(value) > maxValueBytes {
			problems = append(problems, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value is longer than %d bytes", maxValueBytes),
			})
		}
	}

	slices.SortStableFunc(problems, func(first, second ValidationError) int {
		return strings.Compare(first.Path, second.Path)
	})
	return problems
}

func invalidIPs(path string, addresses []string) []ValidationError {
	var problems []ValidationError
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		switch {
		case err != nil:
			problems = append(problems, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("must be an IP address, got %s", quoteValue(address)),
			})
		case parsed.Zone() != "":
			problems = append(problems, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("IP address must not have a zone, got %s", quoteValue(address)),
			})
		}
	}
	return problems
}

func enumExpectation(values []string, value string) string {
	return fmt.Sprintf("must be one of %s, got %s", strings.Join(values, ", "), quoteValue(value))
}
