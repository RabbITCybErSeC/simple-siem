package audit

import (
	"net"
	"time"
)

// Event is one audit record. The database supplies ID and CreatedAt.
type Event struct {
	ID            string         `gorm:"column:id;default:uuidv7();->"`
	EventName     string         `gorm:"column:event_name"`
	EventCategory string         `gorm:"column:event_category"`
	EventOutcome  string         `gorm:"column:event_outcome"`
	ActorType     string         `gorm:"column:actor_type"`
	ActorID       *string        `gorm:"column:actor_id"`
	RequestID     string         `gorm:"column:request_id"`
	TraceID       string         `gorm:"column:trace_id"`
	SourceIP      net.IP         `gorm:"column:source_ip"`
	TargetType    string         `gorm:"column:target_type"`
	TargetID      string         `gorm:"column:target_id"`
	Action        string         `gorm:"column:action"`
	Changes       map[string]any `gorm:"column:changes;serializer:json"`
	Redactions    []string       `gorm:"column:redactions;serializer:json"`
	CreatedAt     time.Time      `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
}

func (Event) TableName() string {
	return "audit_events"
}
