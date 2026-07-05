package redactrus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNewRedactors_TableDriven(t *testing.T) {
	cases := []struct {
		name     string
		redactor RedactionFunc
		input    string
		want     string
	}{
		// JWT
		{
			name:     "JWT basic",
			redactor: JWT,
			input:    "token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			want:     "token is [REDACTED]",
		},
		{
			name:     "JWT no match",
			redactor: JWT,
			input:    "this is not a jwt: abc",
			want:     "this is not a jwt: abc",
		},
		// BearerToken
		{
			name:     "BearerToken space",
			redactor: BearerToken,
			input:    "Authorization: Bearer abc-123_token+=",
			want:     "Authorization: Bearer [REDACTED]",
		},
		{
			name:     "BearerToken case insensitive",
			redactor: BearerToken,
			input:    "Authorization: BEARER abc-123",
			want:     "Authorization: BEARER [REDACTED]",
		},
		{
			name:     "BearerToken multi spaces",
			redactor: BearerToken,
			input:    "Authorization: Bearer  xyz-789",
			want:     "Authorization: Bearer  [REDACTED]",
		},
		// AWSAccessKey
		{
			name:     "AWSAccessKey ID only",
			redactor: AWSAccessKey,
			input:    "my key AKIAIOSFODNN7EXAMPLE is active",
			want:     "my key [REDACTED] is active",
		},
		{
			name:     "AWSAccessKey Secret only",
			redactor: AWSAccessKey,
			input:    "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:     "aws_secret_access_key=[REDACTED]",
		},
		{
			name:     "AWSAccessKey Secret space & colon",
			redactor: AWSAccessKey,
			input:    "aws_secret_access_key : wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:     "aws_secret_access_key : [REDACTED]",
		},
		{
			name:     "AWSAccessKey both ID and Secret",
			redactor: AWSAccessKey,
			input:    "key AKIAIOSFODNN7EXAMPLE and secret aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:     "key [REDACTED] and secret aws_secret_access_key=[REDACTED]",
		},
		// CreditCard
		{
			name:     "CreditCard dashes",
			redactor: CreditCard,
			input:    "card 1234-5678-9012-3456",
			want:     "card [REDACTED]",
		},
		{
			name:     "CreditCard spaces",
			redactor: CreditCard,
			input:    "card 1234 5678 9012 3456",
			want:     "card [REDACTED]",
		},
		{
			name:     "CreditCard 13 digit",
			redactor: CreditCard,
			input:    "card 1234567890123",
			want:     "card [REDACTED]",
		},
		// SSN
		{
			name:     "SSN standard",
			redactor: SSN,
			input:    "SSN: 000-12-3456",
			want:     "SSN: [REDACTED]",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.redactor(tc.input, "[REDACTED]")
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestSetGlobalHashKey(t *testing.T) {
	key := []byte("my-test-secret-key")
	SetGlobalHashKey(key)
	defer SetGlobalHashKey(nil)

	// Helper to compute HMAC-SHA256 hex
	expectedHash := func(secret string) string {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(secret))
		return "[HASHED:" + hex.EncodeToString(mac.Sum(nil)) + "]"
	}

	// 1. Password redactor (quoted and unquoted)
	t.Run("Password unquoted", func(t *testing.T) {
		input := "password=mysecret"
		want := "password=" + expectedHash("mysecret")
		got := Password(input, "[REDACTED]")
		if got != want {
			t.Errorf("Password(%q) = %q, want %q", input, got, want)
		}
	})

	t.Run("Password double-quoted", func(t *testing.T) {
		input := `password="mysecret"`
		want := `password="` + expectedHash("mysecret") + `"`
		got := Password(input, "[REDACTED]")
		if got != want {
			t.Errorf("Password(%q) = %q, want %q", input, got, want)
		}
	})

	t.Run("Password single-quoted", func(t *testing.T) {
		input := `password='mysecret'`
		want := `password='` + expectedHash("mysecret") + `'`
		got := Password(input, "[REDACTED]")
		if got != want {
			t.Errorf("Password(%q) = %q, want %q", input, got, want)
		}
	})

	// 2. Email redactor
	t.Run("Email", func(t *testing.T) {
		input := "contact user@example.com today"
		want := "contact " + expectedHash("user@example.com") + " today"
		got := Email(input, "[REDACTED]")
		if got != want {
			t.Errorf("Email(%q) = %q, want %q", input, got, want)
		}
	})

	// 3. BearerToken redactor
	t.Run("BearerToken", func(t *testing.T) {
		input := "Authorization: Bearer mytoken123"
		want := "Authorization: Bearer " + expectedHash("mytoken123")
		got := BearerToken(input, "[REDACTED]")
		if got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", input, got, want)
		}
	})
}

func TestSetGlobalRedactionCallback(t *testing.T) {
	type redactionCall struct {
		name  string
		value string
	}
	var calls []redactionCall
	cb := func(redactorName, value string) {
		calls = append(calls, redactionCall{name: redactorName, value: value})
	}

	SetGlobalRedactionCallback(cb)
	defer SetGlobalRedactionCallback(nil)

	// Call password redactor
	Password("password=pass123", "[REDACTED]")

	// Call email redactor
	Email("test@example.com", "[REDACTED]")

	// Call JWT
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	JWT(jwt, "[REDACTED]")

	// Call BearerToken
	BearerToken("Bearer token456", "[REDACTED]")

	// Call AWSAccessKey
	AWSAccessKey("AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "[REDACTED]")

	// Call CreditCard
	CreditCard("1234-5678-9012-3456", "[REDACTED]")

	// Call SSN
	SSN("000-12-3456", "[REDACTED]")

	expectedCalls := []redactionCall{
		{name: "Password", value: "pass123"},
		{name: "Email", value: "test@example.com"},
		{name: "JWT", value: jwt},
		{name: "BearerToken", value: "token456"},
		{name: "AWSAccessKey", value: "AKIAIOSFODNN7EXAMPLE"},
		{name: "AWSAccessKey", value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{name: "CreditCard", value: "1234-5678-9012-3456"},
		{name: "SSN", value: "000-12-3456"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("expected %d callback invocations, got %d", len(expectedCalls), len(calls))
	}

	for i, ec := range expectedCalls {
		if calls[i].name != ec.name || calls[i].value != ec.value {
			t.Errorf("call %d: expected {name: %q, value: %q}, got {name: %q, value: %q}",
				i, ec.name, ec.value, calls[i].name, calls[i].value)
		}
	}
}
