package redactrus

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// makeEntry creates a logrus.Entry with the given message for use in tests.
func makeEntry(msg string) *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &logrus.Entry{
		Logger:  logger,
		Data:    logrus.Fields{},
		Message: msg,
		Level:   logrus.InfoLevel,
		Time:    time.Now(),
	}
}

// TestNewRedactingFormatter_DefaultRedactWith checks that NewRedactingFormatter
// sets RedactWith to "[REDACTED]" and starts with zero redactors.
func TestNewRedactingFormatter_DefaultRedactWith(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{})
	if f.RedactWith != "[REDACTED]" {
		t.Errorf("expected RedactWith to be \"[REDACTED]\", got %q", f.RedactWith)
	}
	if n := len(f.Redactors()); n != 0 {
		t.Errorf("expected 0 redactors, got %d", n)
	}
}

// TestNewDefaultRedactingFormatter checks that the default formatter has 3
// built-in redactors and the standard replacement string.
func TestNewDefaultRedactingFormatter(t *testing.T) {
	f := NewDefaultRedactingFormatter(&logrus.JSONFormatter{})
	if f.RedactWith != "[REDACTED]" {
		t.Errorf("expected RedactWith to be \"[REDACTED]\", got %q", f.RedactWith)
	}
	if n := len(f.Redactors()); n != 3 {
		t.Errorf("expected 3 redactors, got %d", n)
	}
}

// TestSetRedactWith verifies fluent chaining works and the value is stored.
func TestSetRedactWith(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{}).SetRedactWith("***")
	if f.RedactWith != "***" {
		t.Errorf("expected RedactWith to be \"***\", got %q", f.RedactWith)
	}
}

// TestAddRedactor_Chaining verifies the fluent API returns the same pointer
// and that the redactor count increases.
func TestAddRedactor_Chaining(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{})
	f2 := f.AddRedactor(Email)
	if f != f2 {
		t.Error("expected AddRedactor to return the same *RedactingFormatter pointer")
	}
	if n := len(f.Redactors()); n != 1 {
		t.Errorf("expected 1 redactor after AddRedactor, got %d", n)
	}
}

// TestAddRedactors_Multiple verifies that AddRedactors appends all supplied functions.
func TestAddRedactors_Multiple(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{})
	f.AddRedactors(Password, APIKey, Email)
	if n := len(f.Redactors()); n != 3 {
		t.Errorf("expected 3 redactors after AddRedactors, got %d", n)
	}
}

// TestFormat_PasswordRedaction ensures password values are redacted in output.
func TestFormat_PasswordRedaction(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{}).AddRedactor(Password)
	entry := makeEntry("User logged in with password=secret123")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("expected output to contain \"[REDACTED]\"")
	}
	if strings.Contains(s, "secret123") {
		t.Error("expected output NOT to contain the raw secret \"secret123\"")
	}
}

// TestFormat_APIKeyRedaction ensures api_key values are redacted in output.
func TestFormat_APIKeyRedaction(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{}).AddRedactor(APIKey)
	entry := makeEntry("request with api_key=supersecret")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("expected output to contain \"[REDACTED]\"")
	}
	if strings.Contains(s, "supersecret") {
		t.Error("expected output NOT to contain the raw secret \"supersecret\"")
	}
}

// TestFormat_EmailRedaction ensures email addresses are redacted in output.
func TestFormat_EmailRedaction(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{}).AddRedactor(Email)
	entry := makeEntry("sent to user@example.com today")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("expected output to contain \"[REDACTED]\"")
	}
	if strings.Contains(s, "user@example.com") {
		t.Error("expected output NOT to contain the raw email \"user@example.com\"")
	}
}

// TestFormat_AllDefaultRedactors verifies all three default redactors fire
// correctly within a single Format call.
func TestFormat_AllDefaultRedactors(t *testing.T) {
	f := NewDefaultRedactingFormatter(&logrus.JSONFormatter{})
	entry := makeEntry("password=abc, api_key=xyz, user@example.com")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "abc") {
		t.Error("expected output NOT to contain password value \"abc\"")
	}
	if strings.Contains(s, "xyz") {
		t.Error("expected output NOT to contain api_key value \"xyz\"")
	}
	if strings.Contains(s, "user@example.com") {
		t.Error("expected output NOT to contain email \"user@example.com\"")
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("expected output to contain \"[REDACTED]\"")
	}
}

// TestFormat_CustomRedactWith checks that a custom replacement string is used.
func TestFormat_CustomRedactWith(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{}).
		AddRedactor(Email).
		SetRedactWith("<EMAIL>")
	entry := makeEntry("contact admin@corp.com for help")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "<EMAIL>") {
		t.Error("expected output to contain custom redaction token \"<EMAIL>\"")
	}
	if strings.Contains(s, "admin@corp.com") {
		t.Error("expected output NOT to contain raw email \"admin@corp.com\"")
	}
}

// TestFormat_NoRedactors_PassThrough ensures that without any redactors the
// message is emitted verbatim (i.e. sensitive data is NOT redacted).
func TestFormat_NoRedactors_PassThrough(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{})
	entry := makeEntry("password=secret")
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error from Format: %v", err)
	}
	if !strings.Contains(string(out), "password=secret") {
		t.Error("expected raw message to pass through when no redactors are configured")
	}
}

// brokenFormatter is a test helper that always returns an error from Format.
type brokenFormatter struct{}

func (b *brokenFormatter) Format(*logrus.Entry) ([]byte, error) {
	return nil, fmt.Errorf("formatter error")
}

// TestFormat_InnerFormatterError ensures Format propagates inner formatter errors.
func TestFormat_InnerFormatterError(t *testing.T) {
	f := NewRedactingFormatter(&brokenFormatter{}).AddRedactor(Password)
	entry := makeEntry("test")
	_, err := f.Format(entry)
	if err == nil {
		t.Error("expected Format to return a non-nil error when inner formatter fails")
	}
}

// TestConcurrency_Format verifies that concurrent calls to Format and
// concurrent AddRedactor calls do not cause data races or panics.
// Run this test with: go test -race ./...
func TestConcurrency_Format(t *testing.T) {
	f := NewRedactingFormatter(&logrus.JSONFormatter{})
	f.AddRedactor(Password)

	var wg sync.WaitGroup

	// 100 goroutines calling Format concurrently.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := makeEntry("password=secret")
			if _, err := f.Format(entry); err != nil {
				t.Errorf("Format returned unexpected error: %v", err)
			}
		}()
	}

	// 10 goroutines adding redactors concurrently.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.AddRedactor(Email)
		}()
	}

	wg.Wait()
}
