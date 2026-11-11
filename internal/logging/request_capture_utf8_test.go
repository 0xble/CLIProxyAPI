package logging

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8BoundaryNeverSplitsARune(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		max   int
		want  int
	}{
		{name: "budget inside first multibyte rune", value: "\u20acabc", max: 1, want: 0},
		{name: "budget inside first multibyte rune at 2", value: "\u20acabc", max: 2, want: 0},
		{name: "budget exactly after first rune", value: "\u20acabc", max: 3, want: 3},
		{name: "budget inside later rune", value: "a\u20ac", max: 2, want: 1},
		{name: "ascii", value: "abcdef", max: 4, want: 4},
		{name: "fits", value: "ab", max: 4, want: 2},
		{name: "zero budget", value: "abc", max: 0, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateUTF8Boundary(tc.value, tc.max)
			if got != tc.want {
				t.Fatalf("truncateUTF8Boundary(%q, %d) = %d, want %d", tc.value, tc.max, got, tc.want)
			}
			if !utf8.ValidString(tc.value[:got]) {
				t.Fatalf("prefix %q is not valid UTF-8", tc.value[:got])
			}
		})
	}
}
