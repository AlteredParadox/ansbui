package prom

import "testing"

func TestHostFromLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"web1.example.com:9100", "web1.example.com"},
		{"web1.example.com", "web1.example.com"},
		{"203.0.113.7:9100", "203.0.113.7"},
		{"[2001:db8::1]:9100", "2001:db8::1"},
		{"[2001:db8::2]:9100", "2001:db8::2"}, // must not collide with ::1
		{"2001:db8::1", "2001:db8::1"},        // bare v6, no port
		{"[2001:db8::1]", "2001:db8::1"},      // bracketed, no port
		{"", ""},
	}
	for _, c := range cases {
		got := hostFromLabel(map[string]string{"instance": c.in}, "instance")
		if got != c.want {
			t.Errorf("hostFromLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
