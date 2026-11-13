package database

import (
	"errors"
	"slices"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestAppliedVersions(t *testing.T) {
	migrationResult := func(version int64) *goose.MigrationResult {
		return &goose.MigrationResult{Source: &goose.Source{Version: version}}
	}
	partial := &goose.PartialError{
		Applied: []*goose.MigrationResult{migrationResult(1), migrationResult(2)},
		Failed:  migrationResult(3),
		Err:     errors.New("migration 3 failed"),
	}
	tests := []struct {
		name    string
		results []*goose.MigrationResult
		upErr   error
		want    []int64
	}{
		{
			name:    "successful run",
			results: []*goose.MigrationResult{migrationResult(1), migrationResult(2)},
			want:    []int64{1, 2},
		},
		{
			name:  "partial error",
			upErr: partial,
			want:  []int64{1, 2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := appliedVersions(test.results, test.upErr)
			if !slices.Equal(got, test.want) {
				t.Errorf("appliedVersions() = %v, want %v", got, test.want)
			}
		})
	}
}
