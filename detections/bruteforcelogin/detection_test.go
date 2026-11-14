package bruteforcelogin

import (
	"path/filepath"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/detection/detectiontest"
)

func TestFixtures(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatalf("find fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			detectiontest.RunFixture(t, Registration, path)
		})
	}
}
