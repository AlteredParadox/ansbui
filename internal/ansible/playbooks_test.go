package ansible

import (
	"reflect"
	"strings"
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

// TestIncludesIgnoreBlockScalarContent is the security case: a
// `# ansbui-include:` line inside a block scalar is data, not an
// annotation. Honouring it let text in a `shell: |` body widen the
// operator's --limit to hosts they had not selected, since ansible
// treats a comma-separated --limit as a union.
func TestIncludesIgnoreBlockScalarContent(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"literal block", `- hosts: web1
  tasks:
    - name: install
      shell: |
        echo installing
        # ansbui-include: all
        echo done
`},
		{"folded block", `- hosts: web1
  tasks:
    - name: note
      shell: >
        # ansbui-include: dbservers
`},
		{"chomping indicator", `- hosts: web1
  tasks:
    - shell: |-
        # ansbui-include: all
`},
		{"keep indicator", `- hosts: web1
  tasks:
    - shell: |+
        # ansbui-include: all
`},
		{"explicit indentation indicator", `- hosts: web1
  tasks:
    - shell: |2
        # ansbui-include: all
`},
		{"sequence item block scalar", `- hosts: web1
  vars:
    scripts:
      - |
        # ansbui-include: all
`},
		{"blank lines inside the block do not end it", `- hosts: web1
  tasks:
    - shell: |
        echo one

        # ansbui-include: all
`},
		{"block header with trailing comment", `- hosts: web1
  tasks:
    - shell: | # inline note
        # ansbui-include: all
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseIncludesFromYAML(c.yaml); len(got) != 0 {
				t.Errorf("include honoured from block-scalar content: %v", got)
			}
		})
	}
}

// The other direction, and the one that must not regress: genuine
// comments are still annotations, including after a block scalar has
// closed. Over-tightening here would silently narrow a run's targets.
func TestIncludesStillHonouredOutsideBlockScalars(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"top-level comment", "# ansbui-include: db1\n- hosts: web1\n", []string{"db1"}},
		{"indented comment", "- hosts: web1\n  # ansbui-include: db1, db2\n  tasks: []\n", []string{"db1", "db2"}},
		{"after a block scalar dedents", `- hosts: web1
  tasks:
    - shell: |
        echo hi
  # ansbui-include: db1
`, []string{"db1"}},
		{"comment between two block scalars", `- hosts: web1
  tasks:
    - shell: |
        echo one
    # ansbui-include: db1
    - shell: |
        echo two
`, []string{"db1"}},
		{"value that merely starts with a pipe is not a block", `- hosts: web1
  vars:
    msg: |pipe-ish
  # ansbui-include: db1
`, []string{"db1"}},
		{"url value does not open a block", `- hosts: web1
  vars:
    url: http://example.com
  # ansbui-include: db1
`, []string{"db1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseIncludesFromYAML(c.yaml)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestOpensBlockScalar(t *testing.T) {
	opens := []string{
		"shell: |", "  shell: >", "    script: |-", "a: |+", "b: |2",
		"- |", "  - >", "cmd: | # trailing note",
	}
	for _, s := range opens {
		if !opensBlockScalar(s) {
			t.Errorf("opensBlockScalar(%q) = false, want true", s)
		}
	}
	notOpens := []string{
		"", "hosts: web1", "url: http://example.com", `msg: "a | b"`,
		"msg: |pipe-ish", "# a comment", "- name: task", "key:",
	}
	for _, s := range notOpens {
		if opensBlockScalar(s) {
			t.Errorf("opensBlockScalar(%q) = true, want false", s)
		}
	}
}

// stripBlockScalars must preserve line count so any future
// line-number reporting over the stripped text stays accurate.
func TestStripBlockScalarsPreservesLineCount(t *testing.T) {
	in := "- hosts: web1\n  tasks:\n    - shell: |\n        one\n        two\n  vars: {}\n"
	got := stripBlockScalars(in)
	if a, b := strings.Count(in, "\n"), strings.Count(got, "\n"); a != b {
		t.Fatalf("line count changed: %d -> %d", a, b)
	}
	if strings.Contains(got, "one") || strings.Contains(got, "two") {
		t.Errorf("block content survived: %q", got)
	}
	if !strings.Contains(got, "vars: {}") {
		t.Errorf("content after the block was dropped: %q", got)
	}
}
