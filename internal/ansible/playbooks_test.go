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
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
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
		yaml string
		want []string
	}{
		{"# ansbui-include: localhost, prometheus.example.com\n- hosts: all\n", []string{"localhost", "prometheus.example.com"}},
		{"---\n#  ansbui-include:  a,b,c\n- hosts: all\n", []string{"a", "b", "c"}},
		{"  # ansbui-include: indented\n", []string{"indented"}},  // indented comment
		{"- hosts: all\n  tasks: []\n", nil},                       // no annotation
	}
	for _, tc := range cases {
		p := &Playbook{YAML: tc.yaml}
		annotateFromYAML(p)
		if len(p.Include) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(p.Include, tc.want) {
			t.Errorf("annotateFromYAML(%q): got %v want %v", tc.yaml, p.Include, tc.want)
		}
	}
}
