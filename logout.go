package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// LogoutHandler removes the session cookie
type LogoutHandler struct {
	cookieDomain string
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if req.URL.Path != "/logout" || req.Method != http.MethodPost {
		w.WriteHeader(404)
		return
	}

	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    "--",
		Domain:   h.cookieDomain,
		HttpOnly: true,
		MaxAge:   -1,
	}

	http.SetCookie(w, cookie)

	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)
	http.Redirect(w, req, "/login", 302)
}
