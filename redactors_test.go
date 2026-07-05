package redactrus

import (
	"strings"
	"testing"
)

// TestPassword_TableDriven exercises Password redaction across common variants.
func TestPassword_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		replacement string
		wantMatch   bool // whether the replacement string should appear in the output
	}{
		{"basic key=value", "password=secret", "[REDACTED]", true},
		{"case insensitive PASSWORD", "PASSWORD=secret", "[REDACTED]", true},
		{"passwd variant", "passwd=mypass", "[REDACTED]", true},
		{"pwd variant", "pwd=mypass", "[REDACTED]", true},
		{"no password", "user logged in successfully", "[REDACTED]", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := Password(tc.input, tc.replacement)
			got := strings.Contains(result, tc.replacement)
			if got != tc.wantMatch {
				t.Errorf("Password(%q, %q) contains %q = %v, want %v (result: %q)",
					tc.input, tc.replacement, tc.replacement, got, tc.wantMatch, result)
			}
		})
	}
}

// TestPassword_PreservesKeyPrefix verifies that the key prefix (e.g. "password=")
// is kept in the output while the secret value is replaced.
func TestPassword_PreservesKeyPrefix(t *testing.T) {
	result := Password("password=secret123", "[REDACTED]")
	if !strings.Contains(result, "password=") {
		t.Errorf("expected result to contain \"password=\" prefix, got: %q", result)
	}
	if strings.Contains(result, "secret123") {
		t.Errorf("expected result NOT to contain secret value \"secret123\", got: %q", result)
	}
}

// TestAPIKey_TableDriven exercises APIKey redaction across common variants.
func TestAPIKey_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		replacement string
		wantMatch   bool
	}{
		{"api_key variant", "api_key=abc123", "[REDACTED]", true},
		{"apikey variant", "apikey=abc123", "[REDACTED]", true},
		{"api-key variant", "api-key=abc123", "[REDACTED]", true},
		{"case insensitive API_KEY", "API_KEY=abc123", "[REDACTED]", true},
		{"no api key", "user accessed resource", "[REDACTED]", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := APIKey(tc.input, tc.replacement)
			got := strings.Contains(result, tc.replacement)
			if got != tc.wantMatch {
				t.Errorf("APIKey(%q, %q) contains %q = %v, want %v (result: %q)",
					tc.input, tc.replacement, tc.replacement, got, tc.wantMatch, result)
			}
		})
	}
}

// TestAPIKey_PreservesKeyPrefix verifies the key name survives while the secret
// value is replaced.
func TestAPIKey_PreservesKeyPrefix(t *testing.T) {
	result := APIKey("api_key=supersecret", "[REDACTED]")
	if !strings.Contains(result, "api_key=") {
		t.Errorf("expected result to contain \"api_key=\" prefix, got: %q", result)
	}
	if strings.Contains(result, "supersecret") {
		t.Errorf("expected result NOT to contain secret value \"supersecret\", got: %q", result)
	}
}

// TestEmail_TableDriven exercises Email redaction for a variety of inputs.
func TestEmail_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		replacement string
		wantMatch   bool
	}{
		{"basic email", "contact user@example.com today", "[REDACTED]", true},
		{"uppercase domain", "send to USER@EXAMPLE.COM", "[REDACTED]", true},
		{"no email", "no sensitive data here", "[REDACTED]", false},
		{"multiple emails", "from a@b.com to c@d.org", "[REDACTED]", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := Email(tc.input, tc.replacement)
			got := strings.Contains(result, tc.replacement)
			if got != tc.wantMatch {
				t.Errorf("Email(%q, %q) contains %q = %v, want %v (result: %q)",
					tc.input, tc.replacement, tc.replacement, got, tc.wantMatch, result)
			}
		})
	}
}

// TestEmail_MultipleAddresses verifies that all email addresses in a string
// are replaced, not just the first one.
func TestEmail_MultipleAddresses(t *testing.T) {
	input := "from a@b.com to c@d.org"
	result := Email(input, "[REDACTED]")
	if strings.Contains(result, "a@b.com") {
		t.Errorf("expected \"a@b.com\" to be redacted, got: %q", result)
	}
	if strings.Contains(result, "c@d.org") {
		t.Errorf("expected \"c@d.org\" to be redacted, got: %q", result)
	}
}

// BenchmarkPassword measures the throughput of the Password redactor.
func BenchmarkPassword(b *testing.B) {
	msg := "User logged in with password=secretpassword123 today"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Password(msg, "[REDACTED]")
	}
}

// BenchmarkAPIKey measures the throughput of the APIKey redactor.
func BenchmarkAPIKey(b *testing.B) {
	msg := "Request with api_key=supersecretapikey123456 received"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		APIKey(msg, "[REDACTED]")
	}
}

// BenchmarkEmail measures the throughput of the Email redactor.
func BenchmarkEmail(b *testing.B) {
	msg := "Notification sent to user@example.com and admin@company.org"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Email(msg, "[REDACTED]")
	}
}
