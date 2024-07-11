package main

import (
	"github.com/ibreakthecloud/redactrus"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()

	// Initialize RedactingFormatter with default redactors
	redactingFormatter := redactrus.NewDefaultRedactingFormatter(&logrus.TextFormatter{})

	// Set the logger to use the custom RedactingFormatter
	logger.SetFormatter(redactingFormatter)

	// Example log that includes sensitive information
	logger.Info("User logged in with password=secret123, api_key=12345, and email=user@example.com")
}
