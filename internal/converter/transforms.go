package converter

import "strings"

// transforms is the fixed transform library. Every transform is a total
// function from the source string to the value passed to the catalog Set.
var transforms = map[string]func(string) string{
	"trim":               strings.TrimSpace,
	"lowercase":          strings.ToLower,
	"strip_domain":       stripDomain,
	"windows_logon_type": windowsLogonType,
	"dash_as_empty":      dashAsEmpty,
}

func stripDomain(value string) string {
	if index := strings.LastIndex(value, `\`); index >= 0 {
		value = value[index+1:]
	}
	if index := strings.LastIndex(value, "@"); index >= 0 {
		value = value[:index]
	}
	return value
}

func windowsLogonType(value string) string {
	switch value {
	case "2", "11":
		return "INTERACTIVE"
	case "3":
		return "NETWORK"
	case "10":
		return "REMOTE_INTERACTIVE"
	default:
		return "MECHANISM_OTHER"
	}
}

func dashAsEmpty(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
