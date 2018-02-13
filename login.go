package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// CookieName for the session
const CookieName = "ssso-session"

const loginHTML = `
<html>
	<head>
		<title>SSSO</title>
	</head>
	<body>
		<form action="/login" method="post">
			<div>
				<input type="text" placeholder="Enter Username" name="loginname" required/>
				<input type="password" placeholder="Enter Password" name="password" required/>
			</div>

			{{if .Error}}
				<p><strong>{{.Error}}</strong></p>
			{{else}}
			{{end}}

			<div>
				<label for="rememberMe">Remember for one week?</label>
				<input type="checkbox" id="rememberMe" name="remember" value="remember">
			</div>
			<div><input type="submit" name="submit">Login</input></div>
		</form>
	</body>
</html>
`

// LoginHandler handles the login page and requests
type LoginHandler struct {
	cookieDomain string
	store        *Store
}

type LoginContext struct {
	Error string
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	log.Println("Login")
	log.Printf("Headers for login: %v", req.Header)

	if req.URL.Path != "/login" || !(req.Method == http.MethodGet || req.Method == http.MethodPost) {
		w.WriteHeader(404)
		return
	}

	if req.Method == http.MethodGet {
		writeLoginPage(200, LoginContext{}, w)
		return
	}

	creds, err := getCredentials(req)
	if err != nil {
		if err == ErrInvalidCredentials {
			writeLoginPage(401, LoginContext{Error: "Invalid credentials"}, w)
			return
		}
		w.WriteHeader(400)
		return
	}

	session, err := h.store.Login(creds)
	if err != nil {
		writeLoginPage(401, LoginContext{Error: "Invalid credentials"}, w)
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
	http.Redirect(w, req, "/me", 302)
}

func getCredentials(r *http.Request) (Credentials, error) {
	if err := r.ParseForm(); err != nil {
		log.Printf("ERROR parsing form: %s\n", err.Error())
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
		creds.expire = 7 * 24 * time.Hour
	} else {
		creds.expire = 3 * time.Hour
	}

	if agent, found := r.Header["User-Agent"]; found && len(agent) > 0 {
		creds.agent = strings.Join(agent, " ")
	}

	return creds, nil
}

func writeLoginPage(code int, ctx interface{}, w http.ResponseWriter) {
	WriteHTMLTemplate(code, "login.html", loginHTML, ctx, w)
}
