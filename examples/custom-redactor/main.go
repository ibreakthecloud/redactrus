package main

import (
	"fmt"
	"regexp"

	"github.com/ibreakthecloud/redactrus"
	"github.com/sirupsen/logrus"
)

// GitHubToken redacts GitHub personal access tokens from log messages.
func GitHubToken(msg string, r string) string {
	tokenRegex := regexp.MustCompile(`(ghp_|ghs_|github_pat_)[A-Za-z0-9_]+`)
	return tokenRegex.ReplaceAllString(msg, r)
}

func main() {
	logger := logrus.New()
	formatter := redactrus.NewRedactingFormatter(&logrus.JSONFormatter{}).
		AddRedactors(redactrus.Email, GitHubToken).
		SetRedactWith("[REDACTED]")
	logger.SetFormatter(formatter)

	logger.Info(fmt.Sprintf(
		"Authenticated user@example.com with token ghp_abc123XYZ456 and backup ghp_def789",
	))
}