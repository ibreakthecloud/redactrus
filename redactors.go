package redactrus

import (
	"fmt"
	"regexp"
)

// defaultRedactors returns a slice of default redaction functions
func defaultRedactors() []RedactionFunc {
	return []RedactionFunc{Password, APIKey, Email}
}

// Password redacts the password from a log message
func Password(msg string, r string) string {
	passwordPattern := regexp.MustCompile(`password=\S+`)
	return passwordPattern.ReplaceAllString(msg, fmt.Sprintf("password=%s", r))
}

// APIKey redacts the API key from a log message
func APIKey(msg string, r string) string {
	apiKeyPattern := regexp.MustCompile(`api_key=\S+`)
	return apiKeyPattern.ReplaceAllString(msg, fmt.Sprintf("api_key=%s", r))
}

// Email redacts the email from a log message
func Email(msg string, r string) string {
	emailPattern := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	return emailPattern.ReplaceAllString(msg, r)
}
