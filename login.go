package main

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// CookieName for the session
const CookieName = "ssso-session"

// LoginHandler handles the login page and requests
type LoginHandler struct {
	cookieDomain string
	store        *Store
	template     *template.Template
}

// NewLoginHandler returns a handler for login requests
func NewLoginHandler(store *Store, domain, tmplFile string) *LoginHandler {
	t := template.Must(template.New("login.html").ParseFiles(tmplFile))

	return &LoginHandler{
		cookieDomain: domain,
		store:        store,
		template:     t,
	}
}

// LoginContext contains all data for the login template
type LoginContext struct {
	SubmitAction string
	Error        string
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if req.URL.Path != "/login" || !(req.Method == http.MethodGet || req.Method == http.MethodPost) {
		w.WriteHeader(404)
		return
	}

	if req.Method == http.MethodGet {
		context := LoginContext{SubmitAction: "/login"}
		if redirect, found := req.URL.Query()["redirect"]; found && len(redirect) > 0 && len(redirect[0]) > 0 {
			context.SubmitAction += "?redirect=" + url.QueryEscape(redirect[0])
		}
		WriteHTMLTemplate(200, h.template, context, w)
		return
	}

	creds, err := getCredentials(req)
	if err != nil {
		if err == ErrInvalidCredentials {
			WriteHTMLTemplate(401, h.template, LoginContext{Error: "Invalid credentials"}, w)
			return
		}
		logrus.Errorf("Error getting credentials: %s", err.Error())
		w.WriteHeader(400)
		return
	}

	session, err := h.store.Login(creds)
	if err != nil {
		WriteHTMLTemplate(401, h.template, LoginContext{Error: "Invalid credentials"}, w)
		return
	}

	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    session,
		Domain:   h.cookieDomain,
		HttpOnly: true,
		MaxAge:   int(creds.expire.Seconds()),
	}

	http.SetCookie(w, cookie)

	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)

	query := req.URL.Query()
	if redirect, found := query["redirect"]; found && len(redirect) > 0 {
		logrus.Debugf("Redirecting to %s", redirect[0])
		http.Redirect(w, req, redirect[0], 302)
	} else {
		logrus.Debugf("Redirecting to /me")
		http.Redirect(w, req, "/me", 302)
	}
}

func getCredentials(r *http.Request) (Credentials, error) {
	if err := r.ParseForm(); err != nil {
		logrus.Errorf("Error parsing form: %s", err.Error())
		return Credentials{}, err
	}

	loginName, foundLoginName := GetFormString("loginname", r.Form)
	password, foundPassword := GetFormString("password", r.Form)
	remember, foundRememberMe := GetFormCheckboxes("remember", r.Form)

	if !foundLoginName || !foundPassword {
		return Credentials{}, ErrInvalidCredentials
	}

	creds := Credentials{loginName: loginName, password: password}
	if foundRememberMe && len(remember) > 0 && remember[0] == "remember" {
		creds.expire = 2 * 7 * 24 * time.Hour
	} else {
		creds.expire = 3 * time.Hour
	}

	if agent, found := r.Header["User-Agent"]; found && len(agent) > 0 {
		creds.agent = strings.Join(agent, " ")
	}

	return creds, nil
}
