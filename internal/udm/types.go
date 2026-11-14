package udm

import (
	"slices"
	"time"
)

// Event is the typed UDM subset. Detections use the fields directly.
type Event struct {
	Metadata       Metadata          `json:"metadata"`
	Principal      Noun              `json:"principal,omitzero"`
	Target         Noun              `json:"target,omitzero"`
	Network        Network           `json:"network,omitzero"`
	Extensions     Extensions        `json:"extensions,omitzero"`
	SecurityResult SecurityResult    `json:"security_result,omitzero"`
	Additional     map[string]string `json:"additional,omitempty"`
}

type Metadata struct {
	EventTimestamp    time.Time `json:"event_timestamp"`
	EventType         EventType `json:"event_type"`
	IngestedTimestamp time.Time `json:"ingested_timestamp,omitzero"`
	VendorName        string    `json:"vendor_name,omitempty"`
	ProductName       string    `json:"product_name,omitempty"`
	ProductEventType  string    `json:"product_event_type,omitempty"`
	ProductLogID      string    `json:"product_log_id,omitempty"`
	Description       string    `json:"description,omitempty"`
}

type Noun struct {
	IP          []string `json:"ip,omitempty"` // canonical netip form
	Hostname    string   `json:"hostname,omitempty"`
	Port        int      `json:"port,omitempty"`
	User        User     `json:"user,omitzero"`
	Application string   `json:"application,omitempty"`
}

type User struct {
	UserID     string `json:"userid,omitempty"`
	WindowsSID string `json:"windows_sid,omitempty"`
}

type Network struct {
	ApplicationProtocol ApplicationProtocol `json:"application_protocol,omitempty"`
	SessionID           string              `json:"session_id,omitempty"`
}

type Extensions struct {
	Auth Auth `json:"auth,omitzero"`
}

type Auth struct {
	Mechanism AuthMechanism `json:"mechanism,omitempty"`
}

type SecurityResult struct {
	Action      Action `json:"action,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Description string `json:"description,omitempty"`
}

// EventType is the UDM metadata.event_type value.
type EventType string

const (
	EventTypeUserLogin    EventType = "USER_LOGIN"
	EventTypeUserLogout   EventType = "USER_LOGOUT"
	EventTypeGenericEvent EventType = "GENERIC_EVENT"
)

var eventTypeValues = []string{
	string(EventTypeUserLogin),
	string(EventTypeUserLogout),
	string(EventTypeGenericEvent),
}

func (eventType EventType) Valid() bool {
	return slices.Contains(eventTypeValues, string(eventType))
}

// ApplicationProtocol is the UDM network.application_protocol value.
type ApplicationProtocol string

const (
	ApplicationProtocolSSH     ApplicationProtocol = "SSH"
	ApplicationProtocolRDP     ApplicationProtocol = "RDP"
	ApplicationProtocolKRB5    ApplicationProtocol = "KRB5"
	ApplicationProtocolLDAP    ApplicationProtocol = "LDAP"
	ApplicationProtocolHTTP    ApplicationProtocol = "HTTP"
	ApplicationProtocolHTTPS   ApplicationProtocol = "HTTPS"
	ApplicationProtocolUnknown ApplicationProtocol = "UNKNOWN_APPLICATION_PROTOCOL"
)

var applicationProtocolValues = []string{
	string(ApplicationProtocolSSH),
	string(ApplicationProtocolRDP),
	string(ApplicationProtocolKRB5),
	string(ApplicationProtocolLDAP),
	string(ApplicationProtocolHTTP),
	string(ApplicationProtocolHTTPS),
	string(ApplicationProtocolUnknown),
}

func (applicationProtocol ApplicationProtocol) Valid() bool {
	return slices.Contains(applicationProtocolValues, string(applicationProtocol))
}

// AuthMechanism is the UDM extensions.auth.mechanism value.
type AuthMechanism string

const (
	AuthMechanismUsernamePassword  AuthMechanism = "USERNAME_PASSWORD"
	AuthMechanismNetwork           AuthMechanism = "NETWORK"
	AuthMechanismInteractive       AuthMechanism = "INTERACTIVE"
	AuthMechanismRemoteInteractive AuthMechanism = "REMOTE_INTERACTIVE"
	AuthMechanismOther             AuthMechanism = "MECHANISM_OTHER"
)

var authMechanismValues = []string{
	string(AuthMechanismUsernamePassword),
	string(AuthMechanismNetwork),
	string(AuthMechanismInteractive),
	string(AuthMechanismRemoteInteractive),
	string(AuthMechanismOther),
}

func (authMechanism AuthMechanism) Valid() bool {
	return slices.Contains(authMechanismValues, string(authMechanism))
}

// Action is the UDM security_result.action value.
type Action string

const (
	ActionAllow   Action = "ALLOW"
	ActionBlock   Action = "BLOCK"
	ActionUnknown Action = "UNKNOWN_ACTION"
)

var actionValues = []string{
	string(ActionAllow),
	string(ActionBlock),
	string(ActionUnknown),
}

func (action Action) Valid() bool {
	return slices.Contains(actionValues, string(action))
}

// Kind is how the catalog parses and normalizes a field value.
type Kind string

const (
	KindString    Kind = "string"
	KindUserID    Kind = "user_id"
	KindHostname  Kind = "hostname"
	KindIP        Kind = "ip"
	KindPort      Kind = "port"
	KindTimestamp Kind = "timestamp"
	KindEnum      Kind = "enum"
)

// Field is one catalog entry. Paths are resolved through the catalog, with an
// explicit getter and setter per field and no reflection.
type Field struct {
	Path   string
	Kind   Kind
	Values []string // allowed values when Kind is KindEnum
	Get    func(event *Event) (string, bool)
	Set    func(event *Event, value string) error
}

// ValidationError is one problem found in an event.
type ValidationError struct {
	Path    string
	Message string
}

func (validationError ValidationError) Error() string {
	return validationError.Path + ": " + validationError.Message
}
