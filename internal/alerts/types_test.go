package alerts

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
)

var testEventTime = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

// runModeRow reads the columns the alert path adds to detection_runs.
type runModeRow struct {
	Mode                  string `gorm:"column:mode"`
	AlertsCreated         int    `gorm:"column:alerts_created"`
	AlertsMerged          int    `gorm:"column:alerts_merged"`
	ProposalsDeduplicated int    `gorm:"column:proposals_deduplicated"`
}

func TestRowModelsRoundTrip(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, "detection-round-trip")

	userName := "alice"
	identity := map[string]*string{"user.name": &userName, "host.name": nil}
	subject := udm.Event{
		Metadata:  udm.Metadata{EventTimestamp: testEventTime, VendorName: "linux"},
		Principal: udm.Noun{Hostname: "web01"},
	}
	alert := alertRow{
		DetectionID:           "detection-round-trip",
		DetectionVersion:      "2026.11.14",
		IdentityHash:          "identity-hash",
		IdentitySchemaVersion: 1,
		Identity:              identity,
		Subject:               subject,
		Summary:               "brute force",
		Details:               map[string]string{"failures": "12"},
		Severity:              "HIGH",
		Coalescing:            true,
		FirstEventAt:          testEventTime,
		LastEventAt:           testEventTime.Add(5 * time.Minute),
		EvidenceCount:         1,
	}
	if err := db.Create(&alert).Error; err != nil {
		t.Fatalf("create alert row: %v", err)
	}
	if alert.ID == "" {
		t.Fatal("alert id is empty, want a database-generated UUID")
	}

	sourceKey := dataset.SourceKey{FetcherInstanceID: "fetcher-1", Index: "auth-*", DocumentID: "doc-1"}
	evidence := evidenceRow{
		AlertID:           alert.ID,
		SourceKeyHash:     sourceKey.Hash(),
		FetcherInstanceID: sourceKey.FetcherInstanceID,
		SourceIndex:       sourceKey.Index,
		DocumentID:        sourceKey.DocumentID,
		EventTime:         testEventTime,
	}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create evidence row: %v", err)
	}

	occurrence := occurrenceRow{
		AlertID:          alert.ID,
		DetectionRunID:   runID,
		NewEvidenceCount: 1,
		FirstEventAt:     testEventTime,
		LastEventAt:      testEventTime.Add(5 * time.Minute),
	}
	if err := db.Create(&occurrence).Error; err != nil {
		t.Fatalf("create occurrence row: %v", err)
	}

	runtime := runtimeRow{DetectionID: "detection-round-trip", Status: "ENABLED"}
	if err := db.Create(&runtime).Error; err != nil {
		t.Fatalf("create runtime row: %v", err)
	}

	var storedAlert alertRow
	if err := db.First(&storedAlert, "id = ?", alert.ID).Error; err != nil {
		t.Fatalf("read alert row: %v", err)
	}
	if storedAlert.DetectionID != alert.DetectionID {
		t.Errorf("detection id = %q, want %q", storedAlert.DetectionID, alert.DetectionID)
	}
	if storedAlert.IdentitySchemaVersion != 1 {
		t.Errorf("identity schema version = %d, want 1", storedAlert.IdentitySchemaVersion)
	}
	if !reflect.DeepEqual(storedAlert.Identity, identity) {
		t.Errorf("identity = %v, want %v", storedAlert.Identity, identity)
	}
	if !reflect.DeepEqual(storedAlert.Subject, subject) {
		t.Errorf("subject = %+v, want %+v", storedAlert.Subject, subject)
	}
	if !reflect.DeepEqual(storedAlert.Details, alert.Details) {
		t.Errorf("details = %v, want %v", storedAlert.Details, alert.Details)
	}
	if storedAlert.Status != "OPEN" {
		t.Errorf("status = %q, want OPEN", storedAlert.Status)
	}
	if !storedAlert.Coalescing {
		t.Error("coalescing = false, want true")
	}
	if storedAlert.OccurrenceCount != 1 {
		t.Errorf("occurrence count = %d, want 1", storedAlert.OccurrenceCount)
	}
	if storedAlert.EvidenceCount != 1 {
		t.Errorf("evidence count = %d, want 1", storedAlert.EvidenceCount)
	}
	if storedAlert.Version != 1 {
		t.Errorf("version = %d, want 1", storedAlert.Version)
	}
	if !storedAlert.FirstEventAt.UTC().Equal(testEventTime.UTC()) {
		t.Errorf("first event at = %v, want %v", storedAlert.FirstEventAt, testEventTime)
	}
	if !storedAlert.LastEventAt.UTC().Equal(alert.LastEventAt.UTC()) {
		t.Errorf("last event at = %v, want %v", storedAlert.LastEventAt, alert.LastEventAt)
	}
	if storedAlert.CreatedAt == nil || storedAlert.UpdatedAt == nil {
		t.Errorf("created at %v or updated at %v is nil, want database defaults", storedAlert.CreatedAt, storedAlert.UpdatedAt)
	}

	var storedEvidence evidenceRow
	if err := db.First(&storedEvidence, "alert_id = ?", alert.ID).Error; err != nil {
		t.Fatalf("read evidence row: %v", err)
	}
	if !bytes.Equal(storedEvidence.SourceKeyHash, sourceKey.Hash()) {
		t.Errorf("source key hash = %x, want %x", storedEvidence.SourceKeyHash, sourceKey.Hash())
	}
	if storedEvidence.FetcherInstanceID != sourceKey.FetcherInstanceID {
		t.Errorf("fetcher instance id = %q, want %q", storedEvidence.FetcherInstanceID, sourceKey.FetcherInstanceID)
	}
	if storedEvidence.SourceIndex != sourceKey.Index {
		t.Errorf("source index = %q, want %q", storedEvidence.SourceIndex, sourceKey.Index)
	}
	if storedEvidence.DocumentID != sourceKey.DocumentID {
		t.Errorf("document id = %q, want %q", storedEvidence.DocumentID, sourceKey.DocumentID)
	}
	if !storedEvidence.EventTime.UTC().Equal(testEventTime.UTC()) {
		t.Errorf("evidence event time = %v, want %v", storedEvidence.EventTime, testEventTime)
	}
	if storedEvidence.ObservedAt == nil {
		t.Error("evidence observed at is nil, want a database default")
	}

	var storedOccurrence occurrenceRow
	if err := db.First(&storedOccurrence, "id = ?", occurrence.ID).Error; err != nil {
		t.Fatalf("read occurrence row: %v", err)
	}
	if storedOccurrence.ID == "" {
		t.Error("occurrence id is empty, want a database-generated UUID")
	}
	if storedOccurrence.AlertID != alert.ID {
		t.Errorf("occurrence alert id = %q, want %q", storedOccurrence.AlertID, alert.ID)
	}
	if storedOccurrence.DetectionRunID != runID {
		t.Errorf("occurrence run id = %q, want %q", storedOccurrence.DetectionRunID, runID)
	}
	if storedOccurrence.NewEvidenceCount != 1 {
		t.Errorf("occurrence new evidence count = %d, want 1", storedOccurrence.NewEvidenceCount)
	}
	if storedOccurrence.ObservedAt == nil {
		t.Error("occurrence observed at is nil, want a database default")
	}

	var storedRuntime runtimeRow
	if err := db.First(&storedRuntime, "detection_id = ?", runtime.DetectionID).Error; err != nil {
		t.Fatalf("read runtime row: %v", err)
	}
	if storedRuntime.Status != "ENABLED" {
		t.Errorf("runtime status = %q, want ENABLED", storedRuntime.Status)
	}
	if storedRuntime.Reason != nil {
		t.Errorf("runtime reason = %q, want nil", *storedRuntime.Reason)
	}
	if storedRuntime.ChangedAt == nil {
		t.Error("runtime changed at is nil, want a database default")
	}
	if storedRuntime.Version != 1 {
		t.Errorf("runtime version = %d, want 1", storedRuntime.Version)
	}
}

func TestOneOpenCoalescingAlertPerIdentity(t *testing.T) {
	db := databasetest.New(t)

	first := newAlertRow("detection-open-identity", "identity-hash")
	if err := db.Create(&first).Error; err != nil {
		t.Fatalf("create first open alert: %v", err)
	}

	duplicate := newAlertRow("detection-open-identity", "identity-hash")
	err := db.Create(&duplicate).Error
	if err == nil {
		t.Fatal("second open coalescing alert was accepted, want a unique violation")
	}
	if !strings.Contains(err.Error(), "alerts_open_identity") {
		t.Fatalf("create error = %v, want it to name alerts_open_identity", err)
	}

	nonCoalescing := newAlertRow("detection-open-identity", "identity-hash")
	nonCoalescing.Coalescing = false
	if err := db.Create(&nonCoalescing).Error; err != nil {
		t.Fatalf("create a second non-coalescing open alert: %v", err)
	}

	closed := newAlertRow("detection-open-identity", "identity-hash")
	closed.Status = "CLOSED"
	if err := db.Create(&closed).Error; err != nil {
		t.Fatalf("create a closed coalescing alert: %v", err)
	}
}

func TestDetectionRunsDefaults(t *testing.T) {
	db := databasetest.New(t)

	insertRun(t, db, "detection-defaults")
	var stored runModeRow
	err := db.Raw(`
		SELECT mode, alerts_created, alerts_merged, proposals_deduplicated
		FROM detection_runs
		WHERE detection_id = ?`, "detection-defaults").Scan(&stored).Error
	if err != nil {
		t.Fatalf("read detection run defaults: %v", err)
	}
	if stored.Mode != "SHADOW" {
		t.Errorf("mode = %q, want SHADOW", stored.Mode)
	}
	if stored.AlertsCreated != 0 || stored.AlertsMerged != 0 || stored.ProposalsDeduplicated != 0 {
		t.Errorf("counters = %d, %d, %d, want zero", stored.AlertsCreated, stored.AlertsMerged, stored.ProposalsDeduplicated)
	}

	if err := insertRunWithMode(db, "detection-enabled", "ENABLED"); err != nil {
		t.Fatalf("insert a run in ENABLED mode: %v", err)
	}
	var enabled runModeRow
	if err := db.Raw("SELECT mode FROM detection_runs WHERE detection_id = ?", "detection-enabled").Scan(&enabled).Error; err != nil {
		t.Fatalf("read the ENABLED run: %v", err)
	}
	if enabled.Mode != "ENABLED" {
		t.Errorf("mode = %q, want ENABLED", enabled.Mode)
	}

	err = insertRunWithMode(db, "detection-invalid", "OTHER")
	if err == nil {
		t.Fatal("mode OTHER was accepted, want a check violation")
	}
	if !strings.Contains(err.Error(), "detection_runs_mode_check") {
		t.Fatalf("insert error = %v, want it to name detection_runs_mode_check", err)
	}
}

func newAlertRow(detectionID, identityHash string) alertRow {
	return alertRow{
		DetectionID:           detectionID,
		DetectionVersion:      "2026.11.14",
		IdentityHash:          identityHash,
		IdentitySchemaVersion: 1,
		Identity:              map[string]*string{},
		Subject:               udm.Event{},
		Summary:               "test alert",
		Details:               map[string]string{},
		Severity:              "LOW",
		Status:                "OPEN",
		Coalescing:            true,
		FirstEventAt:          testEventTime,
		LastEventAt:           testEventTime,
		EvidenceCount:         1,
	}
}

func insertRun(t *testing.T, db *gorm.DB, detectionID string) string {
	t.Helper()
	runID, err := insertRunRow(db, detectionID, "")
	if err != nil {
		t.Fatalf("insert detection run: %v", err)
	}
	return runID
}

func insertRunWithMode(db *gorm.DB, detectionID, mode string) error {
	_, err := insertRunRow(db, detectionID, mode)
	return err
}

// insertRunRow inserts one detection_runs row. An empty mode leaves the column
// at its database default.
func insertRunRow(db *gorm.DB, detectionID, mode string) (string, error) {
	columns := "detection_id, detection_version, status, window_start, window_end, revision, started_at"
	values := "?, '2026.11.14', 'OK', ?, ?, 1, ?"
	arguments := []any{detectionID, testEventTime, testEventTime.Add(time.Hour), testEventTime}
	if mode != "" {
		columns += ", mode"
		values += ", ?"
		arguments = append(arguments, mode)
	}
	var runID string
	err := db.Raw(
		"INSERT INTO detection_runs ("+columns+") VALUES ("+values+") RETURNING id::text",
		arguments...,
	).Scan(&runID).Error
	return runID, err
}
