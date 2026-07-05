package redactrus

import (
	"regexp"
	"sync"

	"github.com/sirupsen/logrus"
)

// RedactionFunc type for functions that redact sensitive information
type RedactionFunc func(string, string) string

// RedactingFormatter struct that embeds logrus.Formatter and includes redaction functions.
// InnerFormatter and RedactWith are exported; redactors is unexported and protected by mu.
type RedactingFormatter struct {
	InnerFormatter      logrus.Formatter
	RedactWith          string
	mu                  sync.RWMutex
	redactors           []RedactionFunc
	redactFields        map[string]struct{}
	redactFieldPatterns []*regexp.Regexp
}

// NewRedactingFormatter creates a new RedactingFormatter with no redactors.
// RedactWith defaults to "[REDACTED]".
func NewRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter:      innerFormatter,
		redactors:           []RedactionFunc{},
		RedactWith:          "[REDACTED]",
		redactFields:        make(map[string]struct{}),
		redactFieldPatterns: []*regexp.Regexp{},
	}
}

// NewDefaultRedactingFormatter creates a new RedactingFormatter with default redactors.
func NewDefaultRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter {
	return &RedactingFormatter{
		InnerFormatter:      innerFormatter,
		redactors:           defaultRedactors(),
		RedactWith:          "[REDACTED]",
		redactFields:        make(map[string]struct{}),
		redactFieldPatterns: []*regexp.Regexp{},
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

// RedactFields adds one or more specific field keys to be redacted from logrus entry fields.
func (f *RedactingFormatter) RedactFields(keys ...string) *RedactingFormatter {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		f.redactFields[k] = struct{}{}
	}
	return f
}

// RedactFieldsByKeyPattern adds one or more regex patterns to match against entry field keys.
func (f *RedactingFormatter) RedactFieldsByKeyPattern(patterns ...*regexp.Regexp) *RedactingFormatter {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redactFieldPatterns = append(f.redactFieldPatterns, patterns...)
	return f
}

// RedactFieldsList returns a list of exact keys configured for field redaction.
func (f *RedactingFormatter) RedactFieldsList() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	list := make([]string, 0, len(f.redactFields))
	for k := range f.redactFields {
		list = append(list, k)
	}
	return list
}

// RedactFieldPatterns returns a copy of the regex patterns configured for key-pattern field redaction.
func (f *RedactingFormatter) RedactFieldPatterns() []*regexp.Regexp {
	f.mu.RLock()
	defer f.mu.RUnlock()
	patterns := make([]*regexp.Regexp, len(f.redactFieldPatterns))
	copy(patterns, f.redactFieldPatterns)
	return patterns
}

// Format formats the log entry, applying all redaction functions to the output.
func (f *RedactingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	clonedEntry := *entry

	if len(entry.Data) > 0 {
		clonedEntry.Data = make(logrus.Fields, len(entry.Data))
		for k, v := range entry.Data {
			clonedEntry.Data[k] = v
		}

		f.mu.RLock()
		hasFields := len(f.redactFields) > 0
		hasPatterns := len(f.redactFieldPatterns) > 0
		var exactFields map[string]struct{}
		var patterns []*regexp.Regexp
		if hasFields {
			exactFields = make(map[string]struct{}, len(f.redactFields))
			for k := range f.redactFields {
				exactFields[k] = struct{}{}
			}
		}
		if hasPatterns {
			patterns = make([]*regexp.Regexp, len(f.redactFieldPatterns))
			copy(patterns, f.redactFieldPatterns)
		}
		f.mu.RUnlock()

		if hasFields || hasPatterns {
			for k := range clonedEntry.Data {
				if hasFields {
					if _, ok := exactFields[k]; ok {
						clonedEntry.Data[k] = f.RedactWith
						continue
					}
				}
				if hasPatterns {
					matched := false
					for _, pat := range patterns {
						if pat.MatchString(k) {
							clonedEntry.Data[k] = f.RedactWith
							matched = true
							break
						}
					}
					if matched {
						continue
					}
				}
			}
		}
	}

	originalBytes, err := f.InnerFormatter.Format(&clonedEntry)
	if err != nil {
		return nil, err
	}
	originalMsg := string(originalBytes)

	f.mu.RLock()
	snapshot := make([]RedactionFunc, len(f.redactors))
	copy(snapshot, f.redactors)
	f.mu.RUnlock()

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
