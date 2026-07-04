package ansible

import "regexp"

// redactRE matches "password: VALUE" / "passphrase: VALUE" /
// "apikey: VALUE" / "secret_api_key: VALUE" shapes in log output,
// including JSON-style quoted keys and `=`-delimited shell arg form.
// Case-insensitive because sources vary (JSON, YAML debug,
// ansible -a "password=..."). The unquoted value alternative runs to
// a structural boundary (comma, brace, bracket, quote, newline)
// rather than to whitespace, so multi-word passphrases are scrubbed
// whole. The key is preserved so readers can tell a secret *was*
// present. The token / api[_-]?key / secret[_-]?api[_-]?key
// alternatives scrub common credential shapes that can echo back in
// command previews, module output, or HTTP error bodies.
var redactRE = regexp.MustCompile(`(?i)"?(password|passphrase|token|api[_-]?key|secret[_-]?api[_-]?key)"?\s*[:=]\s*("[^"]*"|'[^']*'|[^,}\]"\n]+)`)

// sensitiveKeyRE matches structured argument / extra-var keys whose
// values should not be retained in run history. It intentionally
// matches substrings so names like db_password, porkbun_secret_key,
// apiToken, and private_key are all scrubbed.
var sensitiveKeyRE = regexp.MustCompile(`(?i)(password|passphrase|token|secret|api[_-]?key|apikey|private[_-]?key)`)

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
