package main

import (
	"log"
	"net/http"
)

// LogoutHandler removes the session cookie
type LogoutHandler struct{}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	log.Println("Logout")
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
		log.Printf("ERROR reading cookie: %s\n", err.Error())
		w.WriteHeader(400)
		return
	}

	cookie.Value = "--"
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, req, "/login", 302)

	// No need (yet) for invalidating the session server side.
}
