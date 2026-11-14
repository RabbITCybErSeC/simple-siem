package dataset

import (
	"encoding/hex"
	"testing"
)

// The hash is stored in dataset_events, so changing the byte layout would
// orphan every existing row.
func TestSourceKeyHash(t *testing.T) {
	key := SourceKey{FetcherInstanceID: "instance", Index: "index", DocumentID: "doc"}

	if got, want := hex.EncodeToString(key.Hash()), "d8fe9fa63e1a1d605f834ac7513d88a39b050f02171d187a18b14177a50f206b"; got != want {
		t.Fatalf("Hash() = %s, want %s", got, want)
	}

	reordered := SourceKey{FetcherInstanceID: "index", Index: "doc", DocumentID: "instance"}
	if got, other := hex.EncodeToString(key.Hash()), hex.EncodeToString(reordered.Hash()); got == other {
		t.Fatalf("reordering the parts produced the same hash %s", got)
	}
}
