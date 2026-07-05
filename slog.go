package redactrus

import (
	"context"
	"log/slog"
	"regexp"
)

// RedactingHandler wraps an slog.Handler and redacts matching attributes.
type RedactingHandler struct {
	h         slog.Handler
	formatter *RedactingFormatter
}

// NewRedactingHandler creates a new RedactingHandler.
func NewRedactingHandler(h slog.Handler, formatter *RedactingFormatter) *RedactingHandler {
	return &RedactingHandler{
		h:         h,
		formatter: formatter,
	}
}

// Enabled delegates the Enabled check to the inner handler.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.h.Enabled(ctx, level)
}

// WithAttrs returns a new RedactingHandler with the given attributes redacted and added.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &RedactingHandler{
		h:         h.h.WithAttrs(redactAttrs(attrs, h.formatter)),
		formatter: h.formatter,
	}
}

// WithGroup returns a new RedactingHandler wrapping the inner handler with the group.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{
		h:         h.h.WithGroup(name),
		formatter: h.formatter,
	}
}

// Handle copies the record, redacts its attributes, and delegates to the inner handler.
//
//nolint:gocritic // slog.Record is passed by value in slog.Handler interface definition
func (h *RedactingHandler) Handle(ctx context.Context, record slog.Record) error {
	newRecord := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)

	var attrs []slog.Attr
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})

	redactedAttrs := redactAttrs(attrs, h.formatter)
	newRecord.AddAttrs(redactedAttrs...)

	return h.h.Handle(ctx, newRecord)
}

// redactAttrs recursively redacts attributes matching exact fields or pattern rules.
func redactAttrs(attrs []slog.Attr, f *RedactingFormatter) []slog.Attr {
	if len(attrs) == 0 {
		return attrs
	}

	f.mu.RLock()
	exact := make(map[string]struct{}, len(f.redactFields))
	for k := range f.redactFields {
		exact[k] = struct{}{}
	}
	patterns := make([]*regexp.Regexp, len(f.redactFieldPatterns))
	copy(patterns, f.redactFieldPatterns)
	f.mu.RUnlock()

	redacted := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		if attr.Value.Kind() == slog.KindGroup {
			redacted[i] = slog.Attr{
				Key:   attr.Key,
				Value: slog.GroupValue(redactAttrs(attr.Value.Group(), f)...),
			}
			continue
		}

		matched := false
		if _, ok := exact[attr.Key]; ok {
			matched = true
		} else {
			for _, pat := range patterns {
				if pat.MatchString(attr.Key) {
					matched = true
					break
				}
			}
		}

		if matched {
			redacted[i] = slog.String(attr.Key, f.RedactWith)
		} else {
			redacted[i] = attr
		}
	}
	return redacted
}
