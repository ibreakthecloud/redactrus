# Contributing to Redactrus

Thank you for your interest in contributing! Redactrus is a security-focused library, so all contributions are reviewed with an emphasis on correctness and safety.

## Development Setup

### Requirements

- Go 1.21 or later
- [golangci-lint](https://golangci-lint.run/welcome/install/) for local linting

### Getting Started

```bash
git clone https://github.com/ibreakthecloud/redactrus.git
cd redactrus
go mod download
```

## Running Tests

```bash
# Run all tests with race detector
go test -v -race ./...

# Run a specific test
go test -v -run TestPassword ./...

# Run benchmarks
go test -bench=. -benchmem -run='^$' ./...
```

## Running the Linter

```bash
golangci-lint run
```

## Pull Request Guidelines

- **One feature or fix per PR** — keep changes focused
- **Tests are required** — all new code must have tests; the CI will fail without them
- **Benchmarks for redactors** — any new built-in redactor should include a benchmark function
- **Must pass CI** — all checks (build, vet, test with race, lint) must be green
- **Conventional commits** — use `feat:`, `fix:`, `test:`, `chore:`, `docs:` prefixes in commit messages

## Adding a New Built-in Redactor

New redactors in `redactors.go` must follow these rules:

1. **Compile the regex at package level** — declare a `var myPattern = regexp.MustCompile(...)` outside the function
2. **Case-insensitive where applicable** — use `(?i)` flag for key=value style patterns
3. **Preserve key prefix** — use a capture group for the key+separator so the replacement is `"${1}" + r`, not a full-line replacement
4. **No false positives on common strings** — test that the pattern does NOT match typical non-sensitive log lines
5. **Table-driven tests** — include both positive (should redact) and negative (should NOT redact) test cases
6. **Benchmark** — add a `BenchmarkMyRedactor` function
7. **Godoc comment** — document what pattern the redactor matches

### Example Redactor Template

```go
// myPattern matches ...
var myPattern = regexp.MustCompile(`(?i)(mykey[=:\s]+)\S+`)

// MyRedactor redacts <description> from log messages.
func MyRedactor(msg string, r string) string {
	return myPattern.ReplaceAllString(msg, "${1}"+r)
}
```

## Security Considerations

Because Redactrus is a **security library**, we hold contributions to a high standard:

- A redactor that silently misses a pattern is worse than no redactor (false sense of security)
- Regex patterns must be tested against edge cases: JSON encoding, URL encoding, different spacing
- When in doubt, err on the side of broader matching (more redaction) rather than narrower

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.
