# Redactrus

```text
░       ░░░        ░░       ░░░░      ░░░░      ░░░        ░░       ░░░  ░░░░  ░░░      ░░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒
▓       ▓▓▓      ▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓▓      ▓▓
█  ███  ███  ████████  ████  ██        ██  ████  █████  █████  ███  ███  ████  ████████  █
█  ████  ██        ██       ███  ████  ███      ██████  █████  ████  ███      ████      ██
                                                                                          
```

[![Go Reference](https://pkg.go.dev/badge/github.com/ibreakthecloud/redactrus.svg)](https://pkg.go.dev/github.com/ibreakthecloud/redactrus)
[![CI Status](https://github.com/ibreakthecloud/redactrus/actions/workflows/ci.yml/badge.svg)](https://github.com/ibreakthecloud/redactrus/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ibreakthecloud/redactrus)](https://github.com/ibreakthecloud/redactrus)
[![License](https://img.shields.io/github/license/ibreakthecloud/redactrus)](LICENSE)

Redactrus is a high-performance, production-grade security logging library for Go. It intercepts, sanitizes, and redacts sensitive data (such as passwords, API keys, JWTs, credit cards, emails, and SSNs) before it hits your logging sink. 

It provides seamless adapters for **logrus**, standard library **slog**, **zerolog**, and any raw **io.Writer** streams.

---

## Features

- **8+ Built-in Redactors**: Out-of-the-box support for `Password`, `APIKey`, `Email`, `JWT`, `BearerToken`, `AWSAccessKey`, `CreditCard`, and `SSN`.
- **Field-level & String-level Redaction**: Scrub structured JSON fields by exact key name or key pattern, and perform deep regex redaction on message text.
- **HMAC Hash-based Redaction**: Replace sensitive data with deterministic `[HASHED:<hex>]` signatures to correlate events across systems safely.
- **OnRedaction Callbacks**: Monitor and audit potential leaks in real-time.
- **Multi-framework Support**: Works out of the box with `sirupsen/logrus`, `log/slog`, `rs/zerolog`, or any custom writer via `io.Writer`.
- **Zero Allocations & Thread-safe**: Regexes are pre-compiled and access is protected by standard synchronization.

---

## Installation

```sh
go get github.com/ibreakthecloud/redactrus
```

Requires Go 1.23 or newer.

---

## Usage

### 1. Logrus Wrapper (Field & Message Redaction)

```go
import (
	"github.com/ibreakthecloud/redactrus"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	
	// Create formatter wrapping standard logrus formatter
	formatter := redactrus.NewDefaultRedactingFormatter(&logrus.JSONFormatter{}).
		RedactFields("password", "api_key") // Redact structured field keys
		
	logger.SetFormatter(formatter)

	// Will redact message string and structured entry fields
	logger.WithField("password", "123").Info("User logging in with password=123")
}
```

### 2. Standard slog Handler (Go 1.21+)

```go
import (
	"log/slog"
	"os"
	"github.com/ibreakthecloud/redactrus"
)

func main() {
	formatter := redactrus.NewDefaultRedactingFormatter(&logrus.JSONFormatter{}).
		RedactFields("secret_token")

	// Wrap any slog.Handler (e.g. JSONHandler)
	handler := redactrus.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil), formatter)
	logger := slog.New(handler)

	// Replaces value of secret_token with "[REDACTED]"
	logger.Info("sensitive operation", slog.String("secret_token", "supersecret"))
}
```

### 3. Zerolog & Byte-stream Writer Adapter

```go
import (
	"os"
	"github.com/ibreakthecloud/redactrus"
	"github.com/rs/zerolog"
)

func main() {
	formatter := redactrus.NewDefaultRedactingFormatter(&logrus.JSONFormatter{})
	
	// Wrap stdout to intercept and redact raw streams
	writer := redactrus.NewZerologWriter(os.Stdout, formatter)
	logger := zerolog.New(writer).With().Timestamp().Logger()

	logger.Info().Msg("Accessing resource with api_key=sk-abc123XYZ")
}
```

---

## Advanced Features

### Deterministic Hash-based Redaction

Instead of placing generic `[REDACTED]` markers in logs, you can set a global HMAC key. Secrets will be replaced with their HMAC-SHA256 signature, preserving quotes:

```go
// Set key for deterministic hashing
redactrus.SetGlobalHashKey([]byte("my-internal-secure-key-123"))

// A log containing "password=mysecret" becomes:
// "password=[HASHED:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae]"
```

### OnRedaction Auditing Callback

Get notified immediately when sensitive data is intercepted:

```go
redactrus.SetGlobalRedactionCallback(func(redactorName, value string) {
	metrics.IncrementCounter("logs.redacted", "redactor", redactorName)
	if isHighlyCritical(value) {
		alerting.Notify("Security leak detected in logs!")
	}
})
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before opening pull requests or reporting vulnerabilities.

---


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
