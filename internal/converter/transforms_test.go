package converter

import "testing"

func TestTransforms(t *testing.T) {
	if len(transforms) != 5 {
		t.Errorf("transform count = %d, want 5", len(transforms))
	}

	cases := []struct {
		transform string
		value     string
		want      string
	}{
		{"trim", "  alice  ", "alice"},
		{"trim", "\t\n", ""},
		{"trim", "", ""},
		{"lowercase", "ALICE", "alice"},
		{"lowercase", "", ""},
		{"strip_domain", `CORP\alice`, "alice"},
		{"strip_domain", "alice@corp.example", "alice"},
		{"strip_domain", `CORP\alice@corp.example`, "alice"},
		{"strip_domain", "alice", "alice"},
		{"strip_domain", "", ""},
		{"windows_logon_type", "2", "INTERACTIVE"},
		{"windows_logon_type", "11", "INTERACTIVE"},
		{"windows_logon_type", "3", "NETWORK"},
		{"windows_logon_type", "10", "REMOTE_INTERACTIVE"},
		{"windows_logon_type", "5", "MECHANISM_OTHER"},
		{"windows_logon_type", "", "MECHANISM_OTHER"},
		{"dash_as_empty", "-", ""},
		{"dash_as_empty", "value", "value"},
		{"dash_as_empty", "", ""},
	}
	for _, test := range cases {
		t.Run(test.transform+"/"+test.value, func(t *testing.T) {
			transform, ok := transforms[test.transform]
			if !ok {
				t.Fatalf("transform %q is missing", test.transform)
			}
			if got := transform(test.value); got != test.want {
				t.Errorf("transform(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}
