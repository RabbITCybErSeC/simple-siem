package detections

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection/detectiontest"
)

// TestDetectionFixtures checks that every registered detection ships a
// positive, a negative, and at least one edge fixture, that every fixture
// passes, and that every detection package is registered.
func TestDetectionFixtures(t *testing.T) {
	directories := manifestDirectories(t)
	registered := make(map[string]bool, len(All))

	for _, registration := range All {
		manifest, err := config.ParseDetectionManifest(registration.Manifest)
		if err != nil {
			t.Fatalf("registration manifest: %v", err)
		}
		directory, onDisk := directories[string(registration.Manifest)]
		if !onDisk {
			t.Fatalf("detection %s: no package under detections/ embeds this manifest", manifest.ID)
		}
		registered[string(registration.Manifest)] = true

		t.Run(manifest.ID, func(t *testing.T) {
			assertFixturesPresent(t, directory)
			for _, path := range fixturePaths(t, directory) {
				detectiontest.RunFixture(t, registration, path)
			}
		})
	}

	for manifest, directory := range directories {
		if !registered[manifest] {
			t.Errorf("detection package %s is not in detections.All", directory)
		}
	}
}

// manifestDirectories maps the exact bytes of each detection.yaml on disk to
// its package directory.
func manifestDirectories(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("*", "detection.yaml"))
	if err != nil {
		t.Fatalf("find detection manifests: %v", err)
	}
	directories := make(map[string]string, len(paths))
	for _, path := range paths {
		manifest, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		directories[string(manifest)] = filepath.Dir(path)
	}
	return directories
}

// assertFixturesPresent requires the positive and negative fixtures and at
// least one edge fixture.
func assertFixturesPresent(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"positive.json", "negative.json"} {
		path := filepath.Join(directory, "testdata", name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing fixture %s", path)
		}
	}
	edges, err := filepath.Glob(filepath.Join(directory, "testdata", "edge_*.json"))
	if err != nil {
		t.Fatalf("find edge fixtures for %s: %v", directory, err)
	}
	if len(edges) == 0 {
		t.Errorf("missing edge fixture %s", filepath.Join(directory, "testdata", "edge_*.json"))
	}
}

// fixturePaths lists every fixture file of one detection package.
func fixturePaths(t *testing.T, directory string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "testdata", "*.json"))
	if err != nil {
		t.Fatalf("find fixtures for %s: %v", directory, err)
	}
	return paths
}
