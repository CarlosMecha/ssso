package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// LogoutHandler removes the session cookie
type LogoutHandler struct{}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if req.URL.Path != "/logout" || req.Method != http.MethodPost {
		w.WriteHeader(404)
		return
	}

	cookie, err := req.Cookie(CookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, req, "/login", 302)
			return
		}
		logrus.Errorf("Error reading cookie: %s", err.Error())
		w.WriteHeader(400)
		return
	}

	cookie.Value = "--"
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)
	http.Redirect(w, req, "/login", 302)
}
