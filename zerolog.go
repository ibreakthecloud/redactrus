package redactrus

import (
	"io"
)

// NewZerologWriter returns an io.Writer that wraps the provided io.Writer with a RedactingWriter,
// enabling integration with Zerolog's writer-based output.
func NewZerologWriter(w io.Writer, formatter *RedactingFormatter) io.Writer {
	return NewRedactingWriter(w, formatter)
}
