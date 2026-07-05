package redactrus

import (
	"regexp"
)

// Package-level compiled regex patterns for performance.
var (
	passwordPattern = regexp.MustCompile(`(?i)((?:password|passwd|pwd)[=:"\s]+)\S+`)
	apiKeyPattern   = regexp.MustCompile(`(?i)((?:api_key|apikey|api-key)[=:"\s]+)\S+`)
	emailPattern    = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
)

// defaultRedactors returns a slice of default redaction functions.
func defaultRedactors() []RedactionFunc {
	return []RedactionFunc{Password, APIKey, Email}
}

// Password redacts password, passwd, and pwd fields (case-insensitive) from a log message.
func Password(msg, r string) string {
	return passwordPattern.ReplaceAllString(msg, "${1}"+r)
}

// APIKey redacts api_key, apikey, and api-key fields (case-insensitive) from a log message.
func APIKey(msg, r string) string {
	return apiKeyPattern.ReplaceAllString(msg, "${1}"+r)
}

// Email redacts email addresses from a log message.
func Email(msg, r string) string {
	return emailPattern.ReplaceAllString(msg, r)
}
