package redactrus

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

func TestRedactingWriter(t *testing.T) {
	buf := new(bytes.Buffer)
	innerFormatter := NewDefaultRedactingFormatter(&logrus.TextFormatter{DisableColors: true})
	// This includes default redactors like Email, Password, APIKey
	w := NewRedactingWriter(buf, innerFormatter)

	input := []byte("User contact is user@example.com and password=secretkey123")
	n, err := w.Write(input)
	if err != nil {
		t.Fatalf("unexpected error on Write: %v", err)
	}
	if n != len(input) {
		t.Errorf("expected written length %d, got %d", len(input), n)
	}

	output := buf.String()
	if strings.Contains(output, "user@example.com") {
		t.Errorf("email was not redacted: %s", output)
	}
	if strings.Contains(output, "secretkey123") {
		t.Errorf("password was not redacted: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected redacted output, got: %s", output)
	}
}

func TestSlogRedactingHandler(t *testing.T) {
	t.Run("exact and pattern field redaction", func(t *testing.T) {
		buf := new(bytes.Buffer)
		formatter := NewRedactingFormatter(&logrus.JSONFormatter{}) // underlying formatter doesn't matter for the handler itself
		formatter.RedactFields("password", "ssn")
		formatter.RedactFieldsByKeyPattern(regexp.MustCompile(`^api_.*$`))

		jsonHandler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time for deterministic testing
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})
		h := NewRedactingHandler(jsonHandler, formatter)
		logger := slog.New(h)

		logger.Info("user login",
			slog.String("username", "alice"),
			slog.String("password", "supersecret"),
			slog.String("ssn", "123-456-7890"),
			slog.String("api_key", "xyz123"),
			slog.String("api_token", "token_abc"),
			slog.String("other_key", "safe_value"),
		)

		var parsed map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if parsed["username"] != "alice" {
			t.Errorf("expected username to be alice, got %v", parsed["username"])
		}
		if parsed["password"] != "[REDACTED]" {
			t.Errorf("expected password to be [REDACTED], got %v", parsed["password"])
		}
		if parsed["ssn"] != "[REDACTED]" {
			t.Errorf("expected ssn to be [REDACTED], got %v", parsed["ssn"])
		}
		if parsed["api_key"] != "[REDACTED]" {
			t.Errorf("expected api_key to be [REDACTED], got %v", parsed["api_key"])
		}
		if parsed["api_token"] != "[REDACTED]" {
			t.Errorf("expected api_token to be [REDACTED], got %v", parsed["api_token"])
		}
		if parsed["other_key"] != "safe_value" {
			t.Errorf("expected other_key to be safe_value, got %v", parsed["other_key"])
		}
	})

	t.Run("nested group recursion", func(t *testing.T) {
		buf := new(bytes.Buffer)
		formatter := NewRedactingFormatter(&logrus.JSONFormatter{})
		formatter.RedactFields("secret")

		jsonHandler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time for deterministic testing
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})
		h := NewRedactingHandler(jsonHandler, formatter)
		logger := slog.New(h)

		logger.Info("nested test",
			slog.Group("user_info",
				slog.String("name", "bob"),
				slog.String("secret", "my-secret-value"),
				slog.Group("nested_group",
					slog.String("secret", "deep-secret"),
					slog.String("public", "hello"),
				),
			),
		)

		var parsed map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		userInfo, ok := parsed["user_info"].(map[string]interface{})
		if !ok {
			t.Fatalf("user_info group not found in output: %v", parsed)
		}
		if userInfo["name"] != "bob" {
			t.Errorf("expected user_info.name to be bob, got %v", userInfo["name"])
		}
		if userInfo["secret"] != "[REDACTED]" {
			t.Errorf("expected user_info.secret to be [REDACTED], got %v", userInfo["secret"])
		}

		nested, ok := userInfo["nested_group"].(map[string]interface{})
		if !ok {
			t.Fatalf("nested_group not found in user_info: %v", userInfo)
		}
		if nested["secret"] != "[REDACTED]" {
			t.Errorf("expected nested_group.secret to be [REDACTED], got %v", nested["secret"])
		}
		if nested["public"] != "hello" {
			t.Errorf("expected nested_group.public to be hello, got %v", nested["public"])
		}
	})

	t.Run("with attrs and with group propagation", func(t *testing.T) {
		buf := new(bytes.Buffer)
		formatter := NewRedactingFormatter(&logrus.JSONFormatter{})
		formatter.RedactFields("secret")

		jsonHandler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time for deterministic testing
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})
		h := NewRedactingHandler(jsonHandler, formatter)

		// Test WithAttrs
		h2 := h.WithAttrs([]slog.Attr{
			slog.String("secret", "parent-secret"),
			slog.String("common", "info"),
		})

		// Test WithGroup
		h3 := h2.WithGroup("subgroup")

		logger := slog.New(h3)
		logger.Info("msg", slog.String("secret", "child-secret"))

		var parsed map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if parsed["secret"] != "[REDACTED]" {
			t.Errorf("expected parent secret to be redacted, got %v", parsed["secret"])
		}
		if parsed["common"] != "info" {
			t.Errorf("expected common attribute, got %v", parsed["common"])
		}

		subgroup, ok := parsed["subgroup"].(map[string]interface{})
		if !ok {
			t.Fatalf("subgroup not found: %v", parsed)
		}
		if subgroup["secret"] != "[REDACTED]" {
			t.Errorf("expected child secret inside subgroup to be redacted, got %v", subgroup["secret"])
		}
	})
}

func TestZerologWriterIntegration(t *testing.T) {
	buf := new(bytes.Buffer)
	formatter := NewDefaultRedactingFormatter(&logrus.JSONFormatter{})
	// NewZerologWriter returns io.Writer wrapping RedactingWriter
	zw := NewZerologWriter(buf, formatter)

	logger := zerolog.New(zw)
	logger.Info().Str("email", "john.doe@example.com").Str("password", "pwd123").Msg("login attempt")

	output := buf.String()
	if strings.Contains(output, "john.doe@example.com") {
		t.Errorf("email address was not redacted from zerolog output: %s", output)
	}
	if strings.Contains(output, "pwd123") {
		t.Errorf("password was not redacted from zerolog output: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected redacted output, got: %s", output)
	}
}
