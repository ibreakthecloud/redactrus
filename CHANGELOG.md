# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test suite with table-driven unit tests and benchmarks for all built-in redactors
- GitHub Actions CI workflow with Go version matrix (1.21, 1.22, 1.23) and race detector
- `golangci-lint` configuration (`.golangci.yml`)
- `SECURITY.md` with responsible disclosure policy and response SLAs
- `CONTRIBUTING.md` with developer setup and contribution guidelines
- `Redactors()` method on `RedactingFormatter` for safe concurrent inspection of the redactor list
- Field-level redaction APIs: `RedactFields(keys ...string)` and `RedactFieldsByKeyPattern(patterns ...*regexp.Regexp)`
- Formatter inspection APIs: `RedactFieldsList()` and `RedactFieldPatterns()`

### Fixed
- **Performance**: Regex patterns are now compiled once at package initialization (not on every log call)
- **Concurrency**: `RedactingFormatter` is now safe for concurrent use via `sync.RWMutex`
- **Default behaviour**: `NewRedactingFormatter` now defaults `RedactWith` to `"[REDACTED]"` instead of empty string (silent data deletion)
- **Pattern coverage**: `Password` redactor is now case-insensitive and matches `password=`, `passwd=`, and `pwd=` variants
- **Pattern coverage**: `APIKey` redactor is now case-insensitive and matches `api_key=`, `apikey=`, and `api-key=` variants
- Repaired broken example files (`basic-with-text-formatter.go`, `zalgo.go`) that were previously empty
- **Robust matching**: Updated Password and APIKey regex patterns to prevent over-matching on boundaries (JSON structures, comma-separated lists, brackets, braces, semicolons)
- **Quote preservation**: Replaces sensitive data while preserving double and single quotes surrounding the secrets

### Changed
- `Redactors` field on `RedactingFormatter` struct is now unexported (`redactors`); use the new `Redactors()` method to read the list
- Formatter `Format()` now shallow-copies the logrus `Entry` and deep-copies the `entry.Data` map before modification to prevent side-effects on caller entries

