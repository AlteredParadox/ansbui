package ansible

import "regexp"

// sensitiveWords is the single definition of "this key name names a
// secret", shared by the structured-key matcher and the log-text
// matcher below. They used to carry separate lists and disagreed:
// sensitiveKeyRE knew about bare `secret` and `private_key`, redactRE
// did not, so a structured extra-var called client_secret was
// scrubbed while the same name echoed in module output or an HTTP
// error body was written to runs.json in the clear. One list means
// they can't drift apart again.
//
// `passwd` and a key that ENDS in `pass` are in the list because that
// is how Ansible itself spells its connection secrets:
// ansible_become_pass, ansible_ssh_pass, ansible_sudo_pass,
// ansible_su_pass. Without them an operator who supplied the fleet's
// sudo password as an extra-var had it written to runs.json and served
// back by the history API in the clear. `pass\b` rather than `pass`
// so the match needs the word to end there: `ansible_become_pass` and
// `dbPass` are secrets, `passed`, `passenger` and `pass_through_mode`
// are not. It does take `bypass` and `compass` with it, which is the
// cheap side to err on — a redacted flag, not a leaked password.
const sensitiveWords = `password|passphrase|passwd|pass\b|token|secret|api[_-]?key|apikey|private[_-]?key|credential`

// sensitiveKeyRE matches structured argument / extra-var keys whose
// values should not be retained in run history. It intentionally
// matches substrings so names like db_password, porkbun_secret_key,
// apiToken, and private_key are all scrubbed.
var sensitiveKeyRE = regexp.MustCompile(`(?i)(` + sensitiveWords + `)`)

// redactRE matches "<key>: VALUE" / "<key>=VALUE" shapes in log
// output, where <key> is any identifier *containing* one of
// sensitiveWords — client_secret, aws_secret_access_key, db_password,
// private_key. Case-insensitive because sources vary (JSON, YAML
// debug, ansible -a "password=...").
//
// The surrounding [\w.]* is what generalises the match from "the key
// ends in `password`" to "the key contains a secret word anywhere",
// which is what sensitiveKeyRE always meant. It deliberately excludes
// `-` so that hyphenated CLI flags whose *value is not a secret* keep
// rendering in command previews: `--vault-password-file=/dev/fd/3`
// stays readable because `-file` can't be absorbed into the key.
//
// Quoted values allow backslash escapes, so a JSON string like
// {"password":"abc\"tail"} is consumed whole. The naive "[^"]*" this
// replaced stopped at the escaped quote and left `tail"` on disk.
// The unquoted alternative runs to a structural boundary (comma,
// brace, bracket, quote, newline) rather than to whitespace, so
// multi-word passphrases are scrubbed whole. The key is preserved so
// readers can tell a secret *was* present.
//
// A value that is a list or an object is taken up to its closing
// bracket on the same line. The unquoted alternative used to get
// those: it accepted the opening bracket and then stopped at the
// first quote, so `"api_tokens": ["a","b"]` kept every token. One
// level only — a nested value is cut at the first closing bracket —
// which is why anything ansbui builds itself (the command preview,
// the stored replay inputs) is redacted by key from the structured
// value, never by this pattern alone.
var redactRE = regexp.MustCompile(
	`(?i)"?([\w.]*(?:` + sensitiveWords + `)[\w.]*)"?\s*[:=]\s*` +
		`("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[[^\]\n]*\]|\{[^}\n]*\}|[^,}\]"\n]+)`)

// RedactText scrubs common credential key/value shapes from a single
// line before it is streamed to the browser or written to disk.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	return redactRE.ReplaceAllString(s, "${1}: <REDACTED>")
}

// RedactEvent returns evt with its Text field scrubbed. Other fields
// (Host, Status, Stream) don't carry user output, so they pass through.
func RedactEvent(evt Event) Event {
	evt.Text = RedactText(evt.Text)
	return evt
}

func RedactStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if sensitiveKeyRE.MatchString(k) {
			out[k] = "<REDACTED>"
			continue
		}
		out[k] = RedactText(v)
	}
	return out
}

func RedactAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if sensitiveKeyRE.MatchString(k) {
			out[k] = "<REDACTED>"
			continue
		}
		out[k] = redactAnyValue(v)
	}
	return out
}

func redactAnyValue(v any) any {
	switch x := v.(type) {
	case string:
		return RedactText(x)
	case map[string]any:
		return RedactAnyMap(x)
	case map[string]string:
		return RedactStringMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactAnyValue(item)
		}
		return out
	default:
		return v
	}
}

// RedactRunRecord returns a copy safe to persist or return over the
// API. It scrubs replay inputs and log text, preserving non-sensitive
// shape where possible.
func RedactRunRecord(rec RunRecord) RunRecord {
	rec.Args = RedactStringMap(rec.Args)
	rec.ExtraVars = RedactAnyMap(rec.ExtraVars)
	rec.Command = RedactText(rec.Command)
	if len(rec.Log) > 0 {
		log := make([]Event, len(rec.Log))
		for i, evt := range rec.Log {
			log[i] = RedactEvent(evt)
		}
		rec.Log = log
	}
	return rec
}
