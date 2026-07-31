package ansible

import (
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
