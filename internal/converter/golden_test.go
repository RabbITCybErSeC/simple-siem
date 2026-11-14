package converter_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
)

func TestShippedMappingsGolden(t *testing.T) {
	mappings, err := converter.LoadMappings([]string{
		"../../config/mappings/ecs-ssh-login.yaml",
		"../../config/mappings/ecs-windows-logon.yaml",
	})
	if err != nil {
		t.Fatalf("LoadMappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mapping count = %d, want 2", len(mappings))
	}
	if mappings[0].ID != "ecs-ssh-login" || mappings[1].ID != "ecs-windows-logon" {
		t.Fatalf("mapping ids = [%s %s], want [ecs-ssh-login ecs-windows-logon]", mappings[0].ID, mappings[1].ID)
	}

	converterInstance, err := converter.New(mappings, 72*time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Date(2026, time.May, 11, 12, 0, 0, 0, time.UTC)
	entries, err := os.ReadDir("testdata/ecs")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	fixtures := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".want.json") {
			continue
		}
		fixtures++
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("testdata/ecs", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			result := converterInstance.Convert(payload, now)
			got, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}
			got = append(got, '\n')

			wantPath := filepath.Join("testdata/ecs", strings.TrimSuffix(name, ".json")+".want.json")
			want, err := os.ReadFile(wantPath)
			if err != nil {
				t.Errorf("read want file: %v", err)
				return
			}
			if string(got) != string(want) {
				t.Errorf("result mismatch\n got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
	if fixtures != 9 {
		t.Errorf("fixture count = %d, want 9", fixtures)
	}
}
