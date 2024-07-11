package redactrus

import (
	"github.com/sirupsen/logrus"
)

// RedactionFunc type for functions that redact sensitive information
type RedactionFunc func(string, string) string

// RedactingFormatter struct that embeds logrus.Formatter and includes redaction functions
type RedactingFormatter struct {
	InnerFormatter logrus.Formatter
	Redactors      []RedactionFunc
	RedactWith     string
}

// NewRedactingFormatter creates a new RedactingFormatter
func NewRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter: innerFormatter,
		Redactors:      []RedactionFunc{},
		RedactWith:     "",
	}
}

// defaultRedactors creates a new RedactingFormatter with default redactors
func NewDefaultRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter: innerFormatter,
		Redactors:      defaultRedactors(),
		RedactWith:     "[REDACTED]",
	}
}

// AddRedactor adds a new redaction function to the RedactingFormatter
func (f *RedactingFormatter) AddRedactor(redactor RedactionFunc) *RedactingFormatter {
	f.Redactors = append(f.Redactors, redactor)
	return f
}

// AddRedactors adds multiple redaction functions to the RedactingFormatter
func (f *RedactingFormatter) AddRedactors(redactors ...RedactionFunc) *RedactingFormatter {
	f.Redactors = append(f.Redactors, redactors...)
	return f
}

// Format method for RedactingFormatter
func (f *RedactingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	originalBytes, err := f.InnerFormatter.Format(entry)
	if err != nil {
		return nil, err
	}
	originalMsg := string(originalBytes)

	// Apply each redaction function to the log message
	for _, redactor := range f.Redactors {
		originalMsg = redactor(originalMsg, f.RedactWith)
	}

	return []byte(originalMsg), nil
}

// SetRedactWith sets the string to redact sensitive information with
func (f *RedactingFormatter) SetRedactWith(r string) *RedactingFormatter {
	f.RedactWith = r
	return f
}
