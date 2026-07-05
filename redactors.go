package redactrus

import (
	"regexp"
	"strings"
)

// Package-level compiled regex patterns for performance.
var (
	passwordPattern = regexp.MustCompile(`(?i)(['"]?(?:password|passwd|pwd)['"]?(?:\s*[=:]\s*|\s+))("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s,;()\[\]]+)`)
	apiKeyPattern   = regexp.MustCompile(`(?i)(['"]?(?:api_key|apikey|api-key)['"]?(?:\s*[=:]\s*|\s+))("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s,;()\[\]]+)`)
	emailPattern    = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
)

// defaultRedactors returns a slice of default redaction functions.
func defaultRedactors() []RedactionFunc {
	return []RedactionFunc{Password, APIKey, Email}
}

// Password redacts password, passwd, and pwd fields (case-insensitive) from a log message.
func Password(msg, r string) string {
	return redactSecret(msg, passwordPattern, r)
}

// APIKey redacts api_key, apikey, and api-key fields (case-insensitive) from a log message.
func APIKey(msg, r string) string {
	return redactSecret(msg, apiKeyPattern, r)
}

// Email redacts email addresses from a log message.
func Email(msg, r string) string {
	return emailPattern.ReplaceAllString(msg, r)
}

func redactSecret(msg string, pattern *regexp.Regexp, r string) string {
	return pattern.ReplaceAllStringFunc(msg, func(match string) string {
		submatches := pattern.FindStringSubmatchIndex(match)
		if len(submatches) < 4 {
			return match
		}
		keyEnd := submatches[3]
		keyPart := match[:keyEnd]
		valuePart := match[keyEnd:]

		if len(valuePart) >= 2 && strings.HasPrefix(valuePart, `"`) && strings.HasSuffix(valuePart, `"`) {
			return keyPart + `"` + r + `"`
		}
		if len(valuePart) >= 2 && strings.HasPrefix(valuePart, `'`) && strings.HasSuffix(valuePart, `'`) {
			return keyPart + `'` + r + `'`
		}
		return keyPart + r
	})
}
