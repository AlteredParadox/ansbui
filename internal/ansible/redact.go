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
// present. The api[_-]?key / secret[_-]?api[_-]?key alternatives
// scrub porkbun's request-body credential shapes that can echo back
// in HTTP error bodies emitted via the bootstrap event stream.
var redactRE = regexp.MustCompile(`(?i)"?(password|passphrase|api[_-]?key|secret[_-]?api[_-]?key)"?\s*[:=]\s*("[^"]*"|'[^']*'|[^,}\]"\n]+)`)

// RedactText scrubs password/passphrase values from a single line.
// Intended for text that is about to be written to disk — callers who
// need the original (e.g. the live WebSocket stream) must use the raw
// string.
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
