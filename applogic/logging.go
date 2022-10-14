package applogic

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type Event struct {
	id      int
	message string
}

type StandardLogger struct {
	*logrus.Logger
}

// Function that creates a logger to use where we need to log smth
func NewLogger() *StandardLogger {
	var baseLogger = logrus.New()
	var standardLogger = &StandardLogger{baseLogger}
	standardLogger.Formatter = &logrus.JSONFormatter{}
	return standardLogger
}

// Vars which specify fields of logging output
var (
	baseInfo = Event{1, "Successful request: %v"}
)

// Method that specifies which var of logging output
// is to be used in logging
func (l *StandardLogger) baseInfo(r *http.Request) {
	l.Println(baseInfo.message, r.Method)

}
