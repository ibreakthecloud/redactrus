# Redactrus

Redactrus is a custom formatter for the [logrus](https://github.com/sirupsen/logrus) logging library, designed to redact sensitive information from your logs. It allows you to define custom redaction functions that can be applied to your log messages, ensuring that sensitive data does not get exposed in your log output.

## Features

- **Custom Redaction Functions**: Define your own redaction logic tailored to your application's needs.
- **Flexible Redaction**: Add single or multiple redactors to your formatter.
- **Easy Integration**: Seamlessly integrates with the logrus logging library.

## Getting Started

To use Redactrus in your project, follow these steps:

### Installation

First, ensure you have logrus installed:

```sh
go get github.com/sirupsen/logrus
```

Then, add Redactrus to your project:

```sh
go get github.com/ibreakthecloud/redactrus
```

### Usage

1. Create a Redacting Formatter:<br>
   You can create a new RedactingFormatter by passing an existing logrus formatter that you wish to wrap. For example, to use logrus's JSONFormatter:

```go
import (
    "github.com/sirupsen/logrus"
    "github.com/ibreakthecloud/redactrus"
)

func main() {
    log := logrus.New()
    formatter := redactrus.NewRedactingFormatter(&logrus.JSONFormatter{})
    log.SetFormatter(formatter)
}
```

2. Add Redaction Functions:<br>
   Define your redaction functions and add them to the formatter:

```go
func myRedactor(originalMsg, redactWith string) string {
    // Implement your redaction logic here
    return originalMsg // Return the redacted message
}

func main() {
    // Assuming log and formatter are already set up
    formatter.AddRedactor(myRedactor)
}
```

3. Log Messages:<br>
   Use logrus as usual, and your logs will be redacted according to your defined rules.

```go
log.Info("This is a log message with password=password123, api_key=abcdef123456, and email=test@example.com.")
```

## RedactingFormatter

RedactingFormatter is a struct that embeds logrus.Formatter and includes redaction functions.

### Methods

- `NewRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter`

  - Creates a new `RedactingFormatter`.

- `NewDefaultRedactingFormatter(innerFormatter logrus.Formatter) *RedactingFormatter`

  - Creates a new `RedactingFormatter` with default redactors.

- `AddRedactor(redactor RedactionFunc) *RedactingFormatter`

  - Adds a new redaction function to the `RedactingFormatter`.

- `AddRedactors(redactors ...RedactionFunc) *RedactingFormatter`

  - Adds multiple redaction functions to the `RedactingFormatter`.

- `SetRedactWith(r string) *RedactingFormatter`
  - Sets the string to redact sensitive information with.

## Default Redactors

The defaultRedactors function returns a slice of default redaction functions: Password, APIKey, and Email.

### Functions

- `Password(msg string, r string) string`
  - Redacts the password from a log message.
- `APIKey(msg string, r string) string`
  - Redacts the API key from a log message.
- `Email(msg string, r string) string`
  -Redacts the email from a log message

## Custom Redaction Functions

You can define your own redaction functions to redact sensitive information from your log messages. A redaction function takes the original log message and the string to redact sensitive information with, and returns the redacted log message.

### Example

```go
func GitHubToken(msg string, r string) string {
    tokenRegex := regexp.MustCompile(`^(gh[ps]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})$`)
    return tokenRegex.ReplaceAllString(msg, r)
}
```

## Contributing

Contributions are welcome! If you have ideas for more custom redactors, it would be awesome to have you contribute them. Feel free to open an issue or submit a pull request. Your contributions can help make Redactrus even more useful for everyone and logging more secure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
