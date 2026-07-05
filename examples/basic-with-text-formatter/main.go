package main

import (
	"github.com/ibreakthecloud/redactrus"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	formatter := redactrus.NewDefaultRedactingFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetFormatter(formatter)
	logger.Info("User logged in with password=secret123, api_key=12345, and email=user@example.com")
	logger.WithField("user", "alice").Info("api_key=sk-abcdef12345 accessed resource")
}
