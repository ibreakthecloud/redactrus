package redactrus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// Package-level compiled regex patterns for performance.
var (
	passwordPattern           = regexp.MustCompile(`(?i)(['"]?(?:password|passwd|pwd)['"]?(?:\s*[=:]\s*|\s+))("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s,;()\[\]]+)`)
	apiKeyPattern             = regexp.MustCompile(`(?i)(['"]?(?:api_key|apikey|api-key)['"]?(?:\s*[=:]\s*|\s+))("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s,;()\[\]]+)`)
	emailPattern              = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	jwtPattern                = regexp.MustCompile(`\b[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b`)
	bearerPattern             = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9-._~+/]+=*)`)
	awsAccessKeyIDPattern     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	awsSecretAccessKeyPattern = regexp.MustCompile(`(?i)(aws_secret_access_key[=:\s]+)([A-Za-z0-9/+=]{40})`)
	creditCardPattern         = regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)
	ssnPattern                = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
)

var (
	hashKey   []byte
	hashKeyMu sync.RWMutex

	redactionCallback   func(redactorName, value string)
	redactionCallbackMu sync.RWMutex
)

// SetGlobalHashKey configures the global hash key used for dynamic HMAC-SHA256 redaction.
func SetGlobalHashKey(key []byte) {
	hashKeyMu.Lock()
	defer hashKeyMu.Unlock()
	if key == nil {
		hashKey = nil
		return
	}
	hashKey = make([]byte, len(key))
	copy(hashKey, key)
}

// SetGlobalRedactionCallback configures the global callback function invoked when a match is redacted.
func SetGlobalRedactionCallback(cb func(redactorName, value string)) {
	redactionCallbackMu.Lock()
	defer redactionCallbackMu.Unlock()
	redactionCallback = cb
}

// defaultRedactors returns a slice of default redaction functions.
func defaultRedactors() []RedactionFunc {
	return []RedactionFunc{Password, APIKey, Email}
}

// Password redacts password, passwd, and pwd fields (case-insensitive) from a log message.
func Password(msg, r string) string {
	return redactSecret(msg, passwordPattern, r, "Password")
}

// APIKey redacts api_key, apikey, and api-key fields (case-insensitive) from a log message.
func APIKey(msg, r string) string {
	return redactSecret(msg, apiKeyPattern, r, "APIKey")
}

// Email redacts email addresses from a log message.
func Email(msg, r string) string {
	return emailPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return redactValue("Email", match, r)
	})
}

// JWT redacts JSON Web Tokens from a log message.
func JWT(msg, r string) string {
	return jwtPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return redactValue("JWT", match, r)
	})
}

// BearerToken redacts Authorization Bearer tokens from a log message.
func BearerToken(msg, r string) string {
	return bearerPattern.ReplaceAllStringFunc(msg, func(match string) string {
		submatches := bearerPattern.FindStringSubmatchIndex(match)
		if len(submatches) < 4 {
			return match
		}
		prefixEnd := submatches[3]
		prefix := match[:prefixEnd]
		token := match[prefixEnd:]
		return prefix + redactValue("BearerToken", token, r)
	})
}

// AWSAccessKey redacts AWS Access Key ID and Secret Access Key from a log message.
func AWSAccessKey(msg, r string) string {
	// First, replace Access Key ID
	msg = awsAccessKeyIDPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return redactValue("AWSAccessKey", match, r)
	})
	// Second, replace Secret Access Key
	msg = awsSecretAccessKeyPattern.ReplaceAllStringFunc(msg, func(match string) string {
		submatches := awsSecretAccessKeyPattern.FindStringSubmatchIndex(match)
		if len(submatches) < 4 {
			return match
		}
		prefixEnd := submatches[3]
		prefix := match[:prefixEnd]
		secret := match[prefixEnd:]
		return prefix + redactValue("AWSAccessKey", secret, r)
	})
	return msg
}

// CreditCard redacts credit card numbers from a log message.
func CreditCard(msg, r string) string {
	return creditCardPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return redactValue("CreditCard", match, r)
	})
}

// SSN redacts Social Security Numbers from a log message.
func SSN(msg, r string) string {
	return ssnPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return redactValue("SSN", match, r)
	})
}

func redactValue(redactorName, val, r string) string {
	redactionCallbackMu.RLock()
	cb := redactionCallback
	redactionCallbackMu.RUnlock()
	if cb != nil {
		cb(redactorName, val)
	}

	hashKeyMu.RLock()
	keyLen := len(hashKey)
	var key []byte
	if keyLen > 0 {
		key = make([]byte, keyLen)
		copy(key, hashKey)
	}
	hashKeyMu.RUnlock()

	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(val))
		return "[HASHED:" + hex.EncodeToString(mac.Sum(nil)) + "]"
	}

	return r
}

func redactSecret(msg string, pattern *regexp.Regexp, r, redactorName string) string {
	return pattern.ReplaceAllStringFunc(msg, func(match string) string {
		submatches := pattern.FindStringSubmatchIndex(match)
		if len(submatches) < 4 {
			return match
		}
		keyEnd := submatches[3]
		keyPart := match[:keyEnd]
		valuePart := match[keyEnd:]

		var rawSecret string
		var quotes string
		if len(valuePart) >= 2 && strings.HasPrefix(valuePart, `"`) && strings.HasSuffix(valuePart, `"`) {
			rawSecret = valuePart[1 : len(valuePart)-1]
			quotes = `"`
		} else if len(valuePart) >= 2 && strings.HasPrefix(valuePart, `'`) && strings.HasSuffix(valuePart, `'`) {
			rawSecret = valuePart[1 : len(valuePart)-1]
			quotes = `'`
		} else {
			rawSecret = valuePart
		}

		redactedVal := redactValue(redactorName, rawSecret, r)
		return keyPart + quotes + redactedVal + quotes
	})
}
