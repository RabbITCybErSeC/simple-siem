package converter_test

import (
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
)

func TestCountsAdd(t *testing.T) {
	counts := converter.Counts{}
	counts.Add(converter.OutcomeConverted)
	counts.Add(converter.OutcomeConverted)
	counts.Add(converter.OutcomeQuarantined)
	counts.Add(converter.OutcomeUnmapped)
	counts.Add(converter.OutcomeLateBeyondRetention)

	if counts.Converted != 2 {
		t.Errorf("converted = %d, want 2", counts.Converted)
	}
	if counts.Quarantined != 1 {
		t.Errorf("quarantined = %d, want 1", counts.Quarantined)
	}
	if counts.Unmapped != 1 {
		t.Errorf("unmapped = %d, want 1", counts.Unmapped)
	}
	if counts.LateBeyondRetention != 1 {
		t.Errorf("late beyond retention = %d, want 1", counts.LateBeyondRetention)
	}
}

func TestFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		counts   converter.Counts
		maxRatio float64
		want     bool
	}{
		{"empty batch", converter.Counts{}, 0.10, false},
		{"99 records all quarantined", converter.Counts{Quarantined: 99}, 0.10, false},
		{"100 records 10 quarantined", converter.Counts{Converted: 90, Quarantined: 10}, 0.10, false},
		{"100 records 11 quarantined", converter.Counts{Converted: 89, Quarantined: 11}, 0.10, true},
		{"100 records 50 quarantined at half", converter.Counts{Converted: 50, Quarantined: 50}, 0.50, false},
		{"100 records 51 quarantined over half", converter.Counts{Converted: 49, Quarantined: 51}, 0.50, true},
		{"100 records all quarantined at one", converter.Counts{Quarantined: 100}, 1.0, false},
		{"100 records all quarantined under one", converter.Counts{Quarantined: 100}, 0.99, true},
		{"100 records one quarantined at zero", converter.Counts{Converted: 99, Quarantined: 1}, 0, true},
		{"100 records none quarantined", converter.Counts{Converted: 100}, 0.10, false},
		{"total includes every outcome", converter.Counts{
			Converted:           80,
			Quarantined:         11,
			Unmapped:            5,
			LateBeyondRetention: 4,
		}, 0.10, true},
		{"unmapped does not count as quarantined", converter.Counts{Converted: 50, Unmapped: 50}, 0.10, false},
		{"101 records 11 quarantined", converter.Counts{Converted: 90, Quarantined: 11}, 0.10, true},
		{"10 quarantined at 0.0999", converter.Counts{Converted: 90, Quarantined: 10}, 0.0999, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := converter.FailsClosed(test.counts, test.maxRatio); got != test.want {
				t.Errorf("FailsClosed(%+v, %v) = %v, want %v", test.counts, test.maxRatio, got, test.want)
			}
		})
	}
}
