package ansible

import (
	"reflect"
	"testing"
)

func TestParseIncludeHosts(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"localhost,prometheus.example.com,vps01", []string{"localhost", "prometheus.example.com", "vps01"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{"a b c", []string{"a", "b", "c"}}, // whitespace-separated
		{"a, , a, b", []string{"a", "b"}},  // dedup + skip empties
		{"", nil},
		{"   ", nil},
	}
	for _, tc := range cases {
		got := parseIncludeHosts(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseIncludeHosts(%q): got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestMergeLimitHosts(t *testing.T) {
	const wantMerged = "vps01,localhost,prometheus"
	cases := []struct {
		userLimit string
		include   []string
		want      string
	}{
		{"vps01", []string{"localhost", "prometheus"}, wantMerged},
		{"", []string{"localhost", "prometheus"}, "localhost,prometheus"},
		{"vps01", nil, "vps01"},
		{"vps01,localhost", []string{"localhost", "prometheus"}, wantMerged}, // dedup
		{"  vps01  ,  localhost ", []string{"prometheus"}, wantMerged},       // trim
		{"localhost", []string{"localhost"}, "localhost"},                    // single dedup
		// Defensive: an include entry containing a literal comma
		// (shape drift from a future caller) is split, not pasted
		// verbatim into the joined limit.
		{"vps01", []string{"localhost,prometheus"}, wantMerged},
	}
	for _, tc := range cases {
		got := MergeLimitHosts(tc.userLimit, tc.include)
		if got != tc.want {
			t.Errorf("MergeLimitHosts(%q, %v): got %q want %q", tc.userLimit, tc.include, got, tc.want)
		}
	}
}

func TestAnnotateFromYAML_Include(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "single annotation",
			yaml: "# ansbui-include: localhost, prometheus.example.com\n- hosts: all\n",
			want: []string{"localhost", "prometheus.example.com"},
		},
		{
			name: "with doc separator and extra spaces",
			yaml: "---\n#  ansbui-include:  a,b,c\n- hosts: all\n",
			want: []string{"a", "b", "c"},
		},
		{
			name: "indented comment",
			yaml: "  # ansbui-include: indented\n",
			want: []string{"indented"},
		},
		{
			name: "no annotation",
			yaml: "- hosts: all\n  tasks: []\n",
			want: nil,
		},
		{
			// Multi-play file with one annotation per play —
			// ansible's --limit is global, so the union (not just
			// the first match) is what should land in --limit.
			name: "two plays each with own annotation",
			yaml: "# ansbui-include: a, b\n- hosts: web\n  tasks: []\n# ansbui-include: c, b\n- hosts: db\n  tasks: []\n",
			want: []string{"a", "b", "c"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Playbook{YAML: tc.yaml}
			annotateFromYAML(p)
			if !reflect.DeepEqual(p.Include, tc.want) {
				t.Errorf("got %v want %v", p.Include, tc.want)
			}
		})
	}
}
