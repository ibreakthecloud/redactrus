package redactrus

import (
	"io"
)

// RedactingWriter wraps an io.Writer and applies string-level redactions to all written data.
type RedactingWriter struct {
	w         io.Writer
	formatter *RedactingFormatter
}

// NewRedactingWriter creates a new RedactingWriter with the given io.Writer and RedactingFormatter.
func NewRedactingWriter(w io.Writer, formatter *RedactingFormatter) *RedactingWriter {
	return &RedactingWriter{
		w:         w,
		formatter: formatter,
	}
}

// Write converts p to a string, runs all string-level redactors from the formatter,
// writes the redacted string to the underlying writer, and returns len(p), nil on success.
func (rw *RedactingWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	msg := string(p)
	redactors := rw.formatter.Redactors()
	for _, redact := range redactors {
		msg = redact(msg, rw.formatter.RedactWith)
	}

	_, err = rw.w.Write([]byte(msg))
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
