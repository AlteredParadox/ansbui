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
	"regexp"
	"strings"
)

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
// first quote, so `"api_tokens": ["a","b"]` kept every token.
//
// Inside the brackets a quoted string is consumed as a unit, so a
// bracket INSIDE a string does not end the value. That matters more
// than it looks: a match that stops in the middle of a string leaves
// the scan out of step with the quotes, and the secret-named key
// further along — which the quoted alternative would have caught —
// is then never matched. `{"credentials":{"password":"abc},SECRET"}}`
// must not come out as `credentials: <REDACTED>,SECRET"}}`.
//
// Nesting: a list may hold objects and an object may hold lists to
// any depth, because the other kind's brackets are ordinary characters
// here. A list inside a list, or an object inside an object, is
// followed one level down; below that the match ends at the first
// closing bracket of its kind. It still ends between tokens, so the
// scan carries on in step and catches later secret-named keys — but
// unnamed elements after that point are left. Which is why anything
// ansbui builds itself (the command preview, the stored replay inputs)
// is redacted by key from the structured value, never by this pattern
// alone.
var redactRE = regexp.MustCompile(
	`(?i)"?([\w.]*(?:` + sensitiveWords + `)[\w.]*)"?\s*[:=]\s*` +
		`(` + reQuoted +
		`|\[(?:` + reQuoted + `|` + reFlatList + `|[^\]\n"'\[])*\]` +
		`|\{(?:` + reQuoted + `|` + reFlatObject + `|[^}\n"'{])*\}` +
		`|[^,}\]"\n]+)`)

// Pieces of redactRE's value alternatives: a quoted string with
// backslash escapes, and a bracketed value with no bracket of its own
// kind inside it (the inner level of the nesting described above).
const (
	reQuoted     = `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`
	reFlatList   = `\[(?:` + reQuoted + `|[^\]\n"'])*\]`
	reFlatObject = `\{(?:` + reQuoted + `|[^}\n"'])*\}`
)

// redactedMarker is what a removed value is replaced with.
const redactedMarker = "<REDACTED>"

// redactionCurrent is the value RunRecord.Redaction is stamped with:
// the generation of rules the record's saved command line was
// produced under.
//
//	0  (records from before the field existed) the "$ ..." line is
//	   the executed command with the pattern applied to its text.
//	1  the "$ ..." line is rendered from inputs redacted by key
//	   before any quoting (buildPlaybookCmd / buildAdhocCmd).
const redactionCurrent = 1

// legacyPreviewCut replaces what followed the first redacted value in
// a generation-0 command line.
//
// It starts with a comma on purpose. The line is scrubbed again at
// every start, and the pattern's unquoted value runs up to the next
// comma: with the comma first, `key: <REDACTED>` matches as it stands
// and the note after it is never absorbed, so a repaired line is
// stable from the first load on.
const legacyPreviewCut = ", … [the rest of this command line was removed — it was recorded before ansbui redacted command lines by value and what followed a redacted value cannot be checked]"

// cutLegacyPreviews makes a generation-0 record's saved command line
// safe to keep.
//
// Such a line can hold the tail of a secret, and no pattern can find
// it now. The old pass matched the start of the value and stopped
// where the shell quoting of a single quote ('"'"') or the quote of a
// list element began; it wrote the marker over the part it matched
// and left the rest. What is on disk is `db_password: <REDACTED>`
// followed by the remainder of the password, with nothing to say
// where that remainder ends. Scrubbing it again matches nothing.
//
// So the line is kept up to and including its first marker and
// dropped from there on. Everything before that point was never under
// a secret-looking name; everything after it cannot be told apart
// from a leftover. The flags that are lost with it (--limit, --tags,
// --check, --become) are still on the record as fields.
//
// A line with no marker had nothing matched in it and is left whole.
func cutLegacyPreviews(rec RunRecord) RunRecord {
	rec.Command = cutAfterFirstRedaction(rec.Command)
	if len(rec.Log) == 0 {
		return rec
	}
	log := make([]Event, len(rec.Log))
	for i, evt := range rec.Log {
		if evt.Type == "meta" && strings.HasPrefix(evt.Text, "$ ") {
			evt.Text = cutAfterFirstRedaction(evt.Text)
		}
		log[i] = evt
	}
	rec.Log = log
	return rec
}

func cutAfterFirstRedaction(text string) string {
	i := strings.Index(text, redactedMarker)
	if i < 0 {
		return text
	}
	end := i + len(redactedMarker)
	if end == len(text) {
		return text
	}
	return text[:end] + legacyPreviewCut
}

// RedactText scrubs common credential key/value shapes from a single
// line before it is streamed to the browser or written to disk.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	return redactRE.ReplaceAllString(s, "${1}: "+redactedMarker)
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
			out[k] = redactedMarker
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
			out[k] = redactedMarker
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
