package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// AuthHandler handles authentication requests
type AuthHandler struct {
	store *Store
}

const (
	// UserHeader contains the login name for the authenticated user
	UserHeader = "X-Auth-User"
	// EmailHeader for the authenticated user
	EmailHeader = "X-Auth-User-Email"
	// NameHeader for the authenticated user
	NameHeader = "X-Auth-User-Name"
	// CookieTokenHeader contains the session cookie value
	CookieTokenHeader = "X-Auth-Cookie-Token"
	// AccessTokenHeader contains the personal access token
	AccessTokenHeader = "X-Auth-Access-Token"
)

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if req.URL.Path != "/authenticate" || req.Method != http.MethodGet {
		w.WriteHeader(404)
		return
	}

	if cookieValue, found := getHeader(CookieTokenHeader, req); found {
		auth, err := h.store.AuthenticateSession(cookieValue)
		h.handleAuth(auth, err, w)
		return
	}

	if accessToken, found := getHeader(AccessTokenHeader, req); found {
		auth, err := h.store.AuthenticateAccessToken(accessToken)
		h.handleAuth(auth, err, w)
		return
	}

	logrus.Debug("Missing auth")
	w.Header()["WWW-Authenticate"] = []string{"Credentials realm=\"Access to SSSO\", charset=\"UTF-8\""}
	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)
	w.WriteHeader(403)
	return
}

func getHeader(name string, req *http.Request) (string, bool) {
	header, found := req.Header[name]
	if found && len(header) == 1 && header[0] != "" {
		return header[0], true
	}
	return "", false
}

func (h *AuthHandler) handleAuth(auth Authorization, err error, w http.ResponseWriter) {
	if err != nil {
		if err == ErrSessionExpired || err == ErrSessionInvalid || err == ErrTokenRevoked || err == ErrTokenInvalid {
			logrus.Debugf("Invalid auth: %s", err.Error())
			w.WriteHeader(401)
			return
		}

		logrus.Errorf("Error auth session: %s", err.Error())
		w.WriteHeader(500)
		return
	}

	headers := w.Header()
	headers[UserHeader] = []string{auth.LoginName}
	headers[EmailHeader] = []string{auth.Email}
	headers[NameHeader] = []string{auth.Name}
	w.WriteHeader(200)
	logrus.Debug("Request to POST /authenticate completed")
}
