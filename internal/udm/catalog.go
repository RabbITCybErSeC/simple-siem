package udm

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const maxValueBytes = 4096

var additionalKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

var catalog = []Field{
	{
		Path: "metadata.event_timestamp",
		Kind: KindTimestamp,
		Get:  func(event *Event) (string, bool) { return timestampValue(event.Metadata.EventTimestamp) },
		Set:  func(event *Event, value string) error { return setTimestamp(&event.Metadata.EventTimestamp, value) },
	},
	{
		Path:   "metadata.event_type",
		Kind:   KindEnum,
		Values: eventTypeValues,
		Get:    func(event *Event) (string, bool) { return nonEmpty(string(event.Metadata.EventType)) },
		Set: func(event *Event, value string) error {
			return setEnum(&event.Metadata.EventType, eventTypeValues, value)
		},
	},
	{
		Path: "metadata.ingested_timestamp",
		Kind: KindTimestamp,
		Get:  func(event *Event) (string, bool) { return timestampValue(event.Metadata.IngestedTimestamp) },
		Set:  func(event *Event, value string) error { return setTimestamp(&event.Metadata.IngestedTimestamp, value) },
	},
	{
		Path: "metadata.vendor_name",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Metadata.VendorName) },
		Set:  func(event *Event, value string) error { return setString(&event.Metadata.VendorName, value) },
	},
	{
		Path: "metadata.product_name",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Metadata.ProductName) },
		Set:  func(event *Event, value string) error { return setString(&event.Metadata.ProductName, value) },
	},
	{
		Path: "metadata.product_event_type",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Metadata.ProductEventType) },
		Set:  func(event *Event, value string) error { return setString(&event.Metadata.ProductEventType, value) },
	},
	{
		Path: "metadata.product_log_id",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Metadata.ProductLogID) },
		Set:  func(event *Event, value string) error { return setString(&event.Metadata.ProductLogID, value) },
	},
	{
		Path: "metadata.description",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Metadata.Description) },
		Set:  func(event *Event, value string) error { return setString(&event.Metadata.Description, value) },
	},
	{
		Path: "principal.ip",
		Kind: KindIP,
		Get:  func(event *Event) (string, bool) { return firstValue(event.Principal.IP) },
		Set:  func(event *Event, value string) error { return appendIP(&event.Principal.IP, value) },
	},
	{
		Path: "principal.hostname",
		Kind: KindHostname,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Principal.Hostname) },
		Set:  func(event *Event, value string) error { return setHostname(&event.Principal.Hostname, value) },
	},
	{
		Path: "principal.port",
		Kind: KindPort,
		Get:  func(event *Event) (string, bool) { return portValue(event.Principal.Port) },
		Set:  func(event *Event, value string) error { return setPort(&event.Principal.Port, value) },
	},
	{
		Path: "principal.user.userid",
		Kind: KindUserID,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Principal.User.UserID) },
		Set:  func(event *Event, value string) error { return setUserID(&event.Principal.User.UserID, value) },
	},
	{
		Path: "target.user.userid",
		Kind: KindUserID,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Target.User.UserID) },
		Set:  func(event *Event, value string) error { return setUserID(&event.Target.User.UserID, value) },
	},
	{
		Path: "target.user.windows_sid",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Target.User.WindowsSID) },
		Set:  func(event *Event, value string) error { return setString(&event.Target.User.WindowsSID, value) },
	},
	{
		Path: "target.hostname",
		Kind: KindHostname,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Target.Hostname) },
		Set:  func(event *Event, value string) error { return setHostname(&event.Target.Hostname, value) },
	},
	{
		Path: "target.ip",
		Kind: KindIP,
		Get:  func(event *Event) (string, bool) { return firstValue(event.Target.IP) },
		Set:  func(event *Event, value string) error { return appendIP(&event.Target.IP, value) },
	},
	{
		Path: "target.port",
		Kind: KindPort,
		Get:  func(event *Event) (string, bool) { return portValue(event.Target.Port) },
		Set:  func(event *Event, value string) error { return setPort(&event.Target.Port, value) },
	},
	{
		Path: "target.application",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Target.Application) },
		Set:  func(event *Event, value string) error { return setString(&event.Target.Application, value) },
	},
	{
		Path:   "network.application_protocol",
		Kind:   KindEnum,
		Values: applicationProtocolValues,
		Get:    func(event *Event) (string, bool) { return nonEmpty(string(event.Network.ApplicationProtocol)) },
		Set: func(event *Event, value string) error {
			return setEnum(&event.Network.ApplicationProtocol, applicationProtocolValues, value)
		},
	},
	{
		Path: "network.session_id",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.Network.SessionID) },
		Set:  func(event *Event, value string) error { return setString(&event.Network.SessionID, value) },
	},
	{
		Path:   "extensions.auth.mechanism",
		Kind:   KindEnum,
		Values: authMechanismValues,
		Get:    func(event *Event) (string, bool) { return nonEmpty(string(event.Extensions.Auth.Mechanism)) },
		Set: func(event *Event, value string) error {
			return setEnum(&event.Extensions.Auth.Mechanism, authMechanismValues, value)
		},
	},
	{
		Path:   "security_result.action",
		Kind:   KindEnum,
		Values: actionValues,
		Get:    func(event *Event) (string, bool) { return nonEmpty(string(event.SecurityResult.Action)) },
		Set: func(event *Event, value string) error {
			return setEnum(&event.SecurityResult.Action, actionValues, value)
		},
	},
	{
		Path: "security_result.summary",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.SecurityResult.Summary) },
		Set:  func(event *Event, value string) error { return setString(&event.SecurityResult.Summary, value) },
	},
	{
		Path: "security_result.description",
		Kind: KindString,
		Get:  func(event *Event) (string, bool) { return nonEmpty(event.SecurityResult.Description) },
		Set:  func(event *Event, value string) error { return setString(&event.SecurityResult.Description, value) },
	},
}

var catalogByPath = func() map[string]Field {
	index := make(map[string]Field, len(catalog))
	for _, field := range catalog {
		index[field.Path] = field
	}
	return index
}()

// Lookup returns the catalog entry for path. additional.<key> resolves as one
// string field per valid key instead of one catalog entry per key.
func Lookup(path string) (Field, bool) {
	if field, ok := catalogByPath[path]; ok {
		return field, true
	}
	key, ok := strings.CutPrefix(path, "additional.")
	if !ok || !additionalKeyPattern.MatchString(key) {
		return Field{}, false
	}
	return Field{
		Path: path,
		Kind: KindString,
		Get: func(event *Event) (string, bool) {
			value, ok := event.Additional[key]
			return value, ok && value != ""
		},
		Set: func(event *Event, raw string) error {
			value, err := normalize(raw)
			if err != nil {
				return err
			}
			if event.Additional == nil {
				event.Additional = make(map[string]string)
			}
			event.Additional[key] = value
			return nil
		},
	}, true
}

// Fields returns every catalog entry.
func Fields() []Field {
	return slices.Clone(catalog)
}

func parseUserID(raw string) (string, error) {
	value, err := normalize(raw)
	if err != nil {
		return "", err
	}
	value = strings.ToLower(value)
	if err := checkLength(value); err != nil {
		return "", err
	}
	return value, nil
}

func parseHostname(raw string) (string, error) {
	value, err := normalize(raw)
	if err != nil {
		return "", err
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if err := checkLength(value); err != nil {
		return "", err
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", errors.New("hostname must not contain whitespace or control characters")
		}
	}
	return value, nil
}

func parseIP(raw string) (string, error) {
	value, err := normalize(raw)
	if err != nil {
		return "", err
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("must be an IP address, got %s", quoteValue(value))
	}
	if address.Zone() != "" {
		return "", fmt.Errorf("IP address must not have a zone, got %s", quoteValue(value))
	}
	return address.Unmap().String(), nil
}

func parsePort(raw string) (int, error) {
	value, err := normalize(raw)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("must be a port number between 0 and 65535, got %s", quoteValue(value))
	}
	return port, nil
}

func parseTimestamp(raw string) (time.Time, error) {
	value, err := normalize(raw)
	if err != nil {
		return time.Time{}, err
	}
	if timestamp, err := time.Parse(time.RFC3339, value); err == nil {
		return timestamp.UTC(), nil
	}
	if milliseconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.UnixMilli(milliseconds).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("must be RFC 3339 or epoch milliseconds, got %s", quoteValue(value))
}

func parseEnum(raw string, values []string) (string, error) {
	value, err := normalize(raw)
	if err != nil {
		return "", err
	}
	if !slices.Contains(values, value) {
		return "", fmt.Errorf("must be one of %s, got %s", strings.Join(values, ", "), quoteValue(value))
	}
	return value, nil
}

func setString(target *string, raw string) error {
	value, err := normalize(raw)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func setUserID(target *string, raw string) error {
	value, err := parseUserID(raw)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func setHostname(target *string, raw string) error {
	value, err := parseHostname(raw)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func appendIP(target *[]string, raw string) error {
	value, err := parseIP(raw)
	if err != nil {
		return err
	}
	*target = append(*target, value)
	return nil
}

func setPort(target *int, raw string) error {
	value, err := parsePort(raw)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func setTimestamp(target *time.Time, raw string) error {
	value, err := parseTimestamp(raw)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func setEnum[T ~string](target *T, values []string, raw string) error {
	value, err := parseEnum(raw, values)
	if err != nil {
		return err
	}
	*target = T(value)
	return nil
}

func normalize(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if err := checkLength(value); err != nil {
		return "", err
	}
	return value, nil
}

func checkLength(value string) error {
	if len(value) > maxValueBytes {
		return fmt.Errorf("value is longer than %d bytes", maxValueBytes)
	}
	return nil
}

func quoteValue(value string) string {
	const limit = 64
	if len(value) > limit {
		value = value[:limit]
	}
	return strconv.Quote(value)
}

func nonEmpty(value string) (string, bool) {
	return value, value != ""
}

func firstValue(values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func portValue(port int) (string, bool) {
	if port == 0 {
		return "", false
	}
	return strconv.Itoa(port), true
}

func timestampValue(timestamp time.Time) (string, bool) {
	if timestamp.IsZero() {
		return "", false
	}
	return timestamp.UTC().Format(time.RFC3339Nano), true
}
