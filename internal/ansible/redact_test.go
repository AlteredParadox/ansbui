package ansible

import "testing"

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
	if got.Args["db_password"] != "<REDACTED>" {
		t.Fatalf("db_password not redacted: %#v", got.Args)
	}
	if got.Args["cmd"] == rec.Args["cmd"] {
		t.Fatalf("arg text not redacted: %#v", got.Args)
	}
	if got.ExtraVars["api_token"] != "<REDACTED>" {
		t.Fatalf("api_token not redacted: %#v", got.ExtraVars)
	}
	nested := got.ExtraVars["config"].(map[string]any)
	if nested["secret_key"] != "<REDACTED>" || nested["region"] != "us-east" {
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
