package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// ErrIdentityMissing reports a required identity value the subject does not
// have, or an identity whose values are all null.
var ErrIdentityMissing = errors.New("identity value is missing")

// ComputeIdentity derives an alert proposal's coalescing identity from its
// subject. Values are read in manifest order, so the hash is stable for one
// identity schema and changes when the fields or their order change. The
// detection version is deliberately not part of it: an upgrade keeps merging.
func ComputeIdentity(detectionID string, alerting config.DetectionAlerting, subject udm.Event) (Identity, error) {
	values := make(map[string]*string, len(alerting.IdentityFields))
	fields := make([][2]any, 0, len(alerting.IdentityFields))
	hasValue := false

	for _, identityField := range alerting.IdentityFields {
		value, found, err := identityValue(identityField.Path, subject)
		if err != nil {
			return Identity{}, err
		}
		if !found && identityField.Fallback != "" {
			value, found, err = identityValue(identityField.Fallback, subject)
			if err != nil {
				return Identity{}, err
			}
		}
		if !found && identityField.Required {
			return Identity{}, fmt.Errorf("%w: %s", ErrIdentityMissing, identityField.Path)
		}

		var stored *string
		if found {
			stored = &value
			hasValue = true
		}
		values[identityField.Path] = stored
		fields = append(fields, [2]any{identityField.Path, stored})
	}

	if !hasValue && alerting.Mode != "ALWAYS_NEW" {
		return Identity{}, fmt.Errorf("%w: all identity fields are null", ErrIdentityMissing)
	}

	input := struct {
		Detection string   `json:"detection"`
		Schema    int      `json:"schema"`
		Fields    [][2]any `json:"fields"`
	}{
		Detection: detectionID,
		Schema:    alerting.IdentitySchemaVersion,
		Fields:    fields,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return Identity{}, fmt.Errorf("encode identity: %w", err)
	}

	sum := sha256.Sum256(encoded)
	return Identity{Hash: hex.EncodeToString(sum[:]), Values: values}, nil
}

// identityValue reads one catalog path. The catalog has already normalized the
// stored value; the trim guards against a hand-built subject.
func identityValue(path string, subject udm.Event) (string, bool, error) {
	field, ok := udm.Lookup(path)
	if !ok {
		return "", false, fmt.Errorf("identity path %q is not in the UDM catalog", path)
	}
	value, found := field.Get(&subject)
	value = strings.TrimSpace(value)
	return value, found && value != "", nil
}
