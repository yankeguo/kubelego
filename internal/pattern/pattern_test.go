package pattern

import "testing"

func TestMatches(t *testing.T) {
	patterns := []string{"*", "prod-*", "app?", "kube-system"}
	if err := Validate(patterns); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		pattern []string
		want    bool
	}{
		{name: "kube-system", pattern: []string{"*"}, want: true},
		{name: "prod-a", pattern: []string{"prod-*"}, want: true},
		{name: "prod", pattern: []string{"prod-*"}, want: false},
		{name: "app1", pattern: []string{"app?"}, want: true},
		{name: "app12", pattern: []string{"app?"}, want: false},
		{name: "staging", pattern: []string{"prod-*", "staging"}, want: true},
		{name: "other", pattern: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Matches(tt.name, tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Matches(%q, %v) = %v, want %v", tt.name, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestValidateRejectsBrokenClass(t *testing.T) {
	if err := Validate([]string{"["}); err == nil {
		t.Fatal("expected an error for an unclosed character class")
	}
}

func TestSplit(t *testing.T) {
	got := Split(" prod-* , staging, ,*")
	want := []string{"prod-*", "staging", "*"}
	if len(got) != len(want) {
		t.Fatalf("Split = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Split = %#v, want %#v", got, want)
		}
	}
}
