package redactrus

import (
	"sync"

	"github.com/sirupsen/logrus"
)

// RedactionFunc type for functions that redact sensitive information
type RedactionFunc func(string, string) string

// RedactingFormatter struct that embeds logrus.Formatter and includes redaction functions.
// InnerFormatter and RedactWith are exported; redactors is unexported and protected by mu.
type RedactingFormatter struct {
	InnerFormatter logrus.Formatter
	RedactWith     string
	mu             sync.RWMutex
	redactors      []RedactionFunc
}

// NewRedactingFormatter creates a new RedactingFormatter with no redactors.
// RedactWith defaults to "[REDACTED]".
func NewRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter: innerFormatter,
		redactors:      []RedactionFunc{},
		RedactWith:     "[REDACTED]",
	}
}

// NewDefaultRedactingFormatter creates a new RedactingFormatter with default redactors.
func NewDefaultRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter: innerFormatter,
		redactors:      defaultRedactors(),
		RedactWith:     "[REDACTED]",
	}
}

// AddRedactor adds a new redaction function to the RedactingFormatter.
func (f *RedactingFormatter) AddRedactor(redactor RedactionFunc) *RedactingFormatter {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redactors = append(f.redactors, redactor)
	return f
}

// AddRedactors adds multiple redaction functions to the RedactingFormatter.
func (f *RedactingFormatter) AddRedactors(redactors ...RedactionFunc) *RedactingFormatter {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redactors = append(f.redactors, redactors...)
	return f
}

// Redactors returns a copy of the current redactors slice for inspection or testing.
func (f *RedactingFormatter) Redactors() []RedactionFunc {
	f.mu.RLock()
	snapshot := make([]RedactionFunc, len(f.redactors))
	copy(snapshot, f.redactors)
	f.mu.RUnlock()
	return snapshot
}

// Format formats the log entry, applying all redaction functions to the output.
func (f *RedactingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	originalBytes, err := f.InnerFormatter.Format(entry)
	if err != nil {
		return nil, err
	}
	originalMsg := string(originalBytes)

	// Take a concurrency-safe snapshot of the redactors slice.
	f.mu.RLock()
	snapshot := make([]RedactionFunc, len(f.redactors))
	copy(snapshot, f.redactors)
	f.mu.RUnlock()

	// Apply each redaction function to the log message without holding the lock.
	for _, redactor := range snapshot {
		originalMsg = redactor(originalMsg, f.RedactWith)
	}

	return []byte(originalMsg), nil
}

// SetRedactWith sets the string to redact sensitive information with.
func (f *RedactingFormatter) SetRedactWith(r string) *RedactingFormatter {
	f.RedactWith = r
	return f
}
