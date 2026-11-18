// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ansible

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const redactedValue = "<REDACTED>"

func TestRedactRunRecordScrubsReplayInputs(t *testing.T) {
	rec := RunRecord{
		Args: map[string]string{
			"cmd":         "echo token=abc123",
			"db_password": "hunter2",
		},
		ExtraVars: map[string]any{
			"api_token": "abc123",
			"config": map[string]any{
				"secret_key": "shh",
				"region":     "us-east",
			},
			"notes": []any{"password=inside text", "safe"},
		},
		Log: []Event{{Type: "line", Text: "password: hunter2"}},
	}

	got := RedactRunRecord(rec)
	if got.Args["db_password"] != redactedValue {
		t.Fatalf("db_password not redacted: %#v", got.Args)
	}
	if got.Args["cmd"] == rec.Args["cmd"] {
		t.Fatalf("arg text not redacted: %#v", got.Args)
	}
	if got.ExtraVars["api_token"] != redactedValue {
		t.Fatalf("api_token not redacted: %#v", got.ExtraVars)
	}
	nested := got.ExtraVars["config"].(map[string]any)
	if nested["secret_key"] != redactedValue || nested["region"] != "us-east" {
		t.Fatalf("nested map redaction wrong: %#v", nested)
	}
	notes := got.ExtraVars["notes"].([]any)
	if notes[0] == "password=inside text" || notes[1] != "safe" {
		t.Fatalf("slice redaction wrong: %#v", notes)
	}
	if got.Log[0].Text == rec.Log[0].Text {
		t.Fatalf("log text not redacted: %#v", got.Log)
	}
}

// TestRedactTextSecretKeyShapes covers the credential shapes that
// used to survive RedactText and land in runs.json in the clear.
// redactRE's key list disagreed with sensitiveKeyRE's: a structured
// extra-var named client_secret was scrubbed, but the same name
// echoed in module output or an HTTP error body was not.
func TestRedactTextSecretKeyShapes(t *testing.T) {
	// Each input carries the literal secret "SHHH" (plus a tail where
	// the escaped-quote bug applied); none of it may survive.
	cases := []struct {
		name string
		in   string
	}{
		{"client_secret shell arg", `client_secret=SHHH`},
		{"client_secret json", `{"client_secret":"SHHH"}`},
		{"aws secret access key", `aws_secret_access_key: SHHH`},
		{"private key yaml", `private_key: SHHH`},
		{"private key json", `{"private_key":"SHHH"}`},
		{"mixed case", `Client_Secret: SHHH`},
		{"dotted key", `auth.token: SHHH`},
		{"credential", `db_credential=SHHH`},
		{"plain password still works", `password: SHHH`},
		{"api key hyphenated", `api-key: SHHH`},
		{"escaped quote in json value", `{"password":"SHHHtail\"more"}`},
		{"single quoted", `password='SHHH'`},
		{"multi-word passphrase", `passphrase: SHHH is a long one`},
		// Ansible's own spellings, and the *_pass convention generally.
		{"ansible_become_pass", `ansible_become_pass: SHHH`},
		{"ansible_ssh_pass json", `{"ansible_ssh_pass":"SHHH"}`},
		{"ansible_sudo_pass shell arg", `ansible_sudo_pass=SHHH`},
		{"ansible_su_pass", `ansible_su_pass: "SHHH"`},
		{"camel case", `dbPass=SHHH`},
		{"bare pass", `pass: SHHH`},
		{"passwd", `mysql_root_passwd: SHHH`},
		// List and object values: every element goes, not just the
		// part before the first quote.
		{"json list", `"api_tokens": ["SHHH-a","SHHH-b"]`},
		{"yaml flow list", `deploy_tokens: [SHHH-a, SHHH-b]`},
		{"json object", `"registry_credential": {"user":"ci","key":"SHHH"}`},
		{"list after other keys", `{"region":"eu","db_password":["SHHH"],"zone":"a"}`},
		// A closing bracket inside a quoted string does not end the
		// value. Stopping there left the rest of the string behind
		// AND put the scan out of step with the quotes, so the
		// secret-named key inside was never matched either.
		{"brace inside a nested secret", `{"credentials":{"password":"abc},SHHH"}}`},
		{"bracket inside a list element", `"api_tokens": ["a]b","SHHH"]`},
		{"brace inside a single-quoted value", `registry_credential: {'a}b': 'SHHH'}`},
		{"escaped quote then a brace", `{"secret":{"k":"a\"},SHHH"}}`},
		{"nested object, secret after it", `{"credentials":{"a":{"b":1},"password":"SHHH"}}`},
		{"nested list, secret after it", `"tokens": [["x"],"SHHH"], "api_token": "SHHH"`},
		{"object in object, unnamed key after it", `"registry_credential": {"a":{"b":1},"k":"SHHH"}`},
		{"yaml list in list", `deploy_tokens: [[a, b], SHHH]`},
		{"list of objects", `"api_tokens": [{"v":"SHHH"},{"v":"SHHH"}]`},
		{"object holding lists", `secret: {"keys":["SHHH","SHHH"],"n":[1,2]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactText(c.in)
			if strings.Contains(got, "SHHH") {
				t.Errorf("secret survived redaction\n in: %s\nout: %s", c.in, got)
			}
			if !strings.Contains(got, redactedValue) {
				t.Errorf("no redaction marker emitted\n in: %s\nout: %s", c.in, got)
			}
		})
	}
}

// TestRedactTextEscapedQuoteLeavesNoTail pins the specific bug: the
// quoted-value branch used to stop at a backslash-escaped quote, so
// the remainder of a JSON string value was written to disk.
func TestRedactTextEscapedQuoteLeavesNoTail(t *testing.T) {
	got := RedactText(`{"password":"abc\"tail"}`)
	for _, leaked := range []string{"abc", "tail"} {
		if strings.Contains(got, leaked) {
			t.Errorf("value fragment %q survived: %s", leaked, got)
		}
	}
}

// TestRedactTextPreservesNonSecrets guards the other direction: the
// broadened key match must not swallow ordinary output, and it must
// leave hyphenated CLI flags whose value is a path (not a secret)
// readable in command previews.
func TestRedactTextPreservesNonSecrets(t *testing.T) {
	keep := []string{
		`ok: [web1] => {"changed": false}`,
		`region: us-east-1`,
		`user: ansible`,
		// The value here is a file descriptor path, not a credential;
		// redacting it would make the vault command preview useless.
		`ansible-vault view x --vault-password-file=/dev/fd/3`,
		// "pass" inside or at the start of a longer word is not a
		// key that ends in pass.
		`passed: 3`,
		`ok: all 12 assertions passed`,
		`pass_through_mode: transparent`,
		`passenger_count: 4`,
		`sshpass -p x ssh host`,
		`TASK [Check the bypass rule is present] ***`,
		// A list or object under an ordinary key is left alone.
		`"tags": ["a","b"]`,
		`ok: [web1] => {"ports": [80, 443]}`,
		`"matrix": [[1,2],[3,4]], "meta": {"a":{"b":"c"}}`,
	}
	for _, s := range keep {
		if got := RedactText(s); got != s {
			t.Errorf("non-secret text was altered\n in: %s\nout: %s", s, got)
		}
	}
}

// TestRedactKeyDefinitionsAgree is the anti-drift check: any key name
// sensitiveKeyRE treats as a secret must also be scrubbed by
// RedactText when it shows up as key: value in log output. These two
// having separate word lists is exactly how the gap arose.
func TestRedactKeyDefinitionsAgree(t *testing.T) {
	keys := []string{
		"password", "db_password", "passphrase", "token", "api_token",
		"secret", "client_secret", "aws_secret_access_key",
		"api_key", "apikey", "api-key", "private_key", "credential",
		"ansible_become_pass", "ansible_ssh_pass", "ansible_sudo_pass",
		"ansible_su_pass", "db_pass", "dbPass", "pass", "passwd",
		"ansible_become_passwd",
	}
	for _, k := range keys {
		if !sensitiveKeyRE.MatchString(k) {
			t.Errorf("sensitiveKeyRE does not consider %q sensitive", k)
		}
		if got := RedactText(k + ": SHHH"); strings.Contains(got, "SHHH") {
			t.Errorf("RedactText left %q value in the clear: %s", k, got)
		}
	}
}

// TestRedactNotSensitiveKeys: the structured-key matcher decides
// whether a whole extra-var or module argument is replaced, so a false
// positive hides an ordinary setting from the operator's own history.
func TestRedactNotSensitiveKeys(t *testing.T) {
	for _, k := range []string{
		"passed", "pass_through_mode", "passenger_count", "password_less_login_ok_count_passes",
		"compass_heading_deg", "region", "state", "user", "become", "path",
	} {
		if k == "password_less_login_ok_count_passes" {
			continue // contains "password": sensitive by the older rule, listed for the reader
		}
		if sensitiveKeyRE.MatchString(k) {
			t.Errorf("sensitiveKeyRE treats %q as a secret", k)
		}
	}
}

// TestRedactLaterPassesRevealNothing: a stored record is redacted
// when it is appended and then served as stored (Recorder.List / Get);
// it is scrubbed again at every start, to pick up new rules. A later
// pass is allowed to trim more — the unquoted-value rule runs to the
// end of the line, so text after an earlier marker can be absorbed —
// but it must never bring a value back, and it must settle.
func TestRedactLaterPassesRevealNothing(t *testing.T) {
	rec := RunRecord{
		Args:      map[string]string{"password": "SHHH'SHHH", "cmd": `echo api_tokens=["SHHH","SHHH"] ansible_become_pass=SHHH`},
		ExtraVars: map[string]any{"ansible_ssh_pass": "SHHH", "list": []any{"token: SHHH", map[string]any{"db_pass": "SHHH"}}},
		Command:   `ansible-playbook x --extra-vars '{"deploy_tokens":["SHHH","SHHH"],"n":1}'`,
		Log: []Event{
			{Type: "line", Text: `"registry_credential": {"user":"ci","key":"SHHH"}, "x": 1`},
			{Type: "line", Text: `ansible_become_pass: SHHH`},
			{Type: "meta", Text: `$ ansible all -a 'password="SHHH"'`},
		},
	}
	texts := func(r RunRecord) []string {
		out := []string{r.Command, r.Args["cmd"], r.Args["password"]}
		for _, e := range r.Log {
			out = append(out, e.Text)
		}
		data, err := json.Marshal(r.ExtraVars)
		if err != nil {
			t.Fatal(err)
		}
		return append(out, string(data))
	}
	cur := rec
	var prev []string
	for pass := 1; pass <= 4; pass++ {
		cur = RedactRunRecord(cur)
		now := texts(cur)
		for _, s := range now {
			if strings.Contains(s, "SHHH") {
				t.Errorf("pass %d left a value in: %s", pass, s)
			}
		}
		if pass == 4 && !reflect.DeepEqual(prev, now) {
			t.Errorf("redaction had not settled after three passes:\n3: %q\n4: %q", prev, now)
		}
		prev = now
	}
}
