package pkg

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents logging levels
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// String returns string representation of log level
func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger represents a logger instance
type Logger struct {
	level  LogLevel
	logger *log.Logger
	prefix string
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

// NewLogger creates a new logger instance
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", 0),
	}
}

// NewLoggerWithPrefix creates a new logger with prefix
func NewLoggerWithPrefix(level LogLevel, prefix string) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", 0),
		prefix: prefix,
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields ...map[string]interface{}) {
	if l.level <= LevelDebug {
		l.log(LevelDebug, message, fields...)
	}
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...map[string]interface{}) {
	if l.level <= LevelInfo {
		l.log(LevelInfo, message, fields...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...map[string]interface{}) {
	if l.level <= LevelWarn {
		l.log(LevelWarn, message, fields...)
	}
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...map[string]interface{}) {
	if l.level <= LevelError {
		l.log(LevelError, message, fields...)
	}
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(message string, fields ...map[string]interface{}) {
	l.log(LevelFatal, message, fields...)
	os.Exit(1)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.level <= LevelDebug {
		l.log(LevelDebug, fmt.Sprintf(format, args...))
	}
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	if l.level <= LevelInfo {
		l.log(LevelInfo, fmt.Sprintf(format, args...))
	}
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	if l.level <= LevelWarn {
		l.log(LevelWarn, fmt.Sprintf(format, args...))
	}
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.level <= LevelError {
		l.log(LevelError, fmt.Sprintf(format, args...))
	}
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *LoggerWithFields {
	return &LoggerWithFields{
		logger: l,
		fields: fields,
	}
}

// log is the internal logging method
func (l *Logger) log(level LogLevel, message string, fields ...map[string]interface{}) {
	timestamp := time.Now().UTC()
	caller := l.getCaller()

	var allFields map[string]interface{}
	if len(fields) > 0 {
		allFields = fields[0]
	}

	// Format log message
	logMsg := l.formatMessage(timestamp, level, message, allFields, caller)
	l.logger.Print(logMsg)
}

// formatMessage formats the log message
func (l *Logger) formatMessage(timestamp time.Time, level LogLevel, message string, fields map[string]interface{}, caller string) string {
	var parts []string

	// Timestamp
	parts = append(parts, timestamp.Format("2006-01-02T15:04:05.000Z"))

	// Level
	parts = append(parts, fmt.Sprintf("[%s]", level.String()))

	// Prefix
	if l.prefix != "" {
		parts = append(parts, fmt.Sprintf("[%s]", l.prefix))
	}

	// Caller
	if caller != "" {
		parts = append(parts, fmt.Sprintf("[%s]", caller))
	}

	// Message
	parts = append(parts, message)

	// Fields
	if len(fields) > 0 {
		var fieldParts []string
		for k, v := range fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("{%s}", strings.Join(fieldParts, ", ")))
	}

	return strings.Join(parts, " ")
}

// getCaller returns the caller information
func (l *Logger) getCaller() string {
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

// LoggerWithFields represents a logger with predefined fields
type LoggerWithFields struct {
	logger *Logger
	fields map[string]interface{}
}

// Debug logs a debug message with predefined fields
func (lwf *LoggerWithFields) Debug(message string) {
	lwf.logger.Debug(message, lwf.fields)
}

// Info logs an info message with predefined fields
func (lwf *LoggerWithFields) Info(message string) {
	lwf.logger.Info(message, lwf.fields)
}

// Warn logs a warning message with predefined fields
func (lwf *LoggerWithFields) Warn(message string) {
	lwf.logger.Warn(message, lwf.fields)
}

// Error logs an error message with predefined fields
func (lwf *LoggerWithFields) Error(message string) {
	lwf.logger.Error(message, lwf.fields)
}

// Fatal logs a fatal message with predefined fields and exits
func (lwf *LoggerWithFields) Fatal(message string) {
	lwf.logger.Fatal(message, lwf.fields)
}
