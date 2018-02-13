package main

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

// WriteHTMLTemplate returns a HTML page with a HTTP code
func WriteHTMLTemplate(code int, t *template.Template, data interface{}, w http.ResponseWriter) {
	w.Header()["Content-Type"] = []string{"text/html"}
	w.WriteHeader(code)
	if err := t.Execute(w, data); err != nil {
		logrus.Errorf("Error writing page: %s", err.Error())
		w.WriteHeader(500)
	}
}

// GetLoginName returns the login name associated with the request
func GetLoginName(req *http.Request) (string, bool) {
	return getHeader(UserHeader, req)
}

// GetFormString returns the string from a HTML Form if found
func GetFormString(key string, form url.Values) (string, bool) {
	value, found := form[key]
	if !found || len(value) != 1 || value[0] == "" {
		return "", false
	}
	return value[0], true
}

// GetFormCheckboxes returns the names of the checkboxes activated for the key
func GetFormCheckboxes(key string, form url.Values) ([]string, bool) {
	values, found := form[key]
	return values, found
}
