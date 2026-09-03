// Package httpx gives every handler one way to fail. A client that always gets
// the same error shape can show a useful message instead of "something went
// wrong", and the code stays readable because handlers return errors instead of
// writing responses in six different places.
package httpx

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Error is what the API returns when a request cannot be satisfied. Code is a
// stable string the client can branch on; Message is for a person to read.
type Error struct {
	Status  int            `json:"-"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

func (e *Error) Error() string { return e.Message }

func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// WithFields attaches per-field detail, so a form can highlight the input that
// is wrong rather than showing one banner at the top.
func (e *Error) WithFields(fields map[string]any) *Error {
	e.Fields = fields
	return e
}

var (
	ErrUnauthorized = New(http.StatusUnauthorized, "unauthorized", "Sign in to continue.")
	ErrForbidden    = New(http.StatusForbidden, "forbidden", "This is not yours to change.")
	ErrNotFound     = New(http.StatusNotFound, "not_found", "That does not exist, or was deleted.")
)

func BadRequest(message string) *Error {
	return New(http.StatusBadRequest, "bad_request", message)
}

func Conflict(code, message string) *Error {
	return New(http.StatusConflict, code, message)
}

// ErrorHandler turns whatever a handler returned into the one JSON shape.
// Anything that is not a known error becomes a 500 with no detail leaked, and
// the real cause goes to the log instead of to the client.
func ErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	var apiErr *Error
	switch {
	case errors.As(err, &apiErr):
	default:
		var echoErr *echo.HTTPError
		if errors.As(err, &echoErr) {
			message, _ := echoErr.Message.(string)
			if message == "" {
				message = http.StatusText(echoErr.Code)
			}
			apiErr = New(echoErr.Code, http.StatusText(echoErr.Code), message)
		} else {
			c.Logger().Error(err)
			apiErr = New(http.StatusInternalServerError, "internal", "Something failed on our side. Try again.")
		}
	}

	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(apiErr.Status)
		return
	}
	_ = c.JSON(apiErr.Status, map[string]any{"error": apiErr})
}
