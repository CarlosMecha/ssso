package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// MeHandler handles personal pages requests
type MeHandler struct {
	store    *Store
	template *template.Template
}

// NewMeHandler creates the handler for /me requests
func NewMeHandler(store *Store, tmplFile string) *MeHandler {
	t := template.Must(template.New("me.html").ParseFiles(tmplFile))

	return &MeHandler{
		store:    store,
		template: t,
	}
}

// MeContext is the context for the me.html page
type MeContext struct {
	Error           string
	PasswordUpdated string
	NewAccessToken  string
	User
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if req.URL.Path != "/me" || (req.Method != http.MethodGet && req.Method != http.MethodPost) {
		w.WriteHeader(404)
		return
	}

	loginName, found := getHeader(UserHeader, req)
	if !found {
		w.WriteHeader(401)
		return
	}

	user, err := h.store.GetUser(loginName)
	if err == ErrUserNotFound {
		logrus.Debug("User not found")
		w.WriteHeader(401)
		return
	} else if err != nil {
		logrus.Fatalf("Unable to retrieve user: %s", err.Error())
		w.WriteHeader(500)
		return
	}

	ctx := MeContext{User: user}

	if req.Method == http.MethodGet {
		if v, found := req.Header["Accept"]; found && len(v) == 1 && strings.Contains(v[0], "json") {
			w.Header()["Content-Type"] = []string{"application/json; charset=utf-8"}
			encoder := json.NewEncoder(w)
			if err := encoder.Encode(user); err != nil {
				logrus.Errorf("Unable to marshal user: %s", err.Error())
				w.WriteHeader(500)
			}
		} else {
			WriteHTMLTemplate(200, h.template, ctx, w)
		}
		return
	}

	if err := req.ParseForm(); err != nil {
		logrus.Errorf("Unable to parse form: %s", err.Error())
		ctx.Error = "Error submitting the form, please try again"
		WriteHTMLTemplate(400, h.template, ctx, w)
		return
	}

	// Update password
	newPassword, foundNewPassword := GetFormString("newPassword", req.Form)
	repeatPassword, foundRepeatPassword := GetFormString("repeatPassword", req.Form)
	if (foundNewPassword || foundRepeatPassword) && (newPassword != "" || repeatPassword != "") {
		if newPassword != repeatPassword {
			ctx.Error = "The new password does not match"
			WriteHTMLTemplate(400, h.template, ctx, w)
		} else if len(newPassword) < 8 || len(newPassword) > 64 {
			ctx.Error = "Invalid new password, introduce a new password between 8 to 64 characters"
			WriteHTMLTemplate(400, h.template, ctx, w)
		}

		password, found := GetFormString("password", req.Form)
		if !found || password == "" {
			ctx.Error = "Please introduce your current password"
			WriteHTMLTemplate(400, h.template, ctx, w)
		}

		if err := h.store.ValidateCredentials(Credentials{loginName: loginName, password: password}); err != nil {
			ctx.Error = "Invalid password"
			WriteHTMLTemplate(400, h.template, ctx, w)
		}

		if err := h.store.UpdatePassword(loginName, newPassword); err != nil {
			ctx.Error = "Error storing new password, pease try again"
			WriteHTMLTemplate(500, h.template, ctx, w)
		}

		ctx.PasswordUpdated = "Your password has been updated"
	}

	// Revoke access tokens
	revokeTokens, found := GetFormCheckboxes("revoke", req.Form)
	if found && len(revokeTokens) > 0 {
		removedTokens := make(map[int]bool, 0)
		for _, value := range revokeTokens {
			tokenID, err := strconv.Atoi(value)
			if err != nil {
				ctx.Error = "Error submitting the form, please try again"
				WriteHTMLTemplate(400, h.template, ctx, w)
				return
			}

			if err := h.store.RevokeAccessToken(loginName, tokenID); err != nil && err != ErrTokenInvalid {
				logrus.Errorf("Error revoking token: %s", err)
				ctx.Error = "Internal error, please try again"
				WriteHTMLTemplate(500, h.template, ctx, w)
				return
			}

			removedTokens[tokenID] = true
		}

		tokens := make([]AccessToken, 0)
		for _, token := range user.AccessTokens {
			if _, found := removedTokens[token.ID]; !found {
				tokens = append(tokens, token)
			}
		}

		ctx.AccessTokens = tokens
	}

	// New access token
	tokenName, found := GetFormString("name", req.Form)
	if found && tokenName != "" {
		tokenID, token, err := h.store.CreateAccessToken(loginName, tokenName)
		if err != nil {
			logrus.Errorf("Error creating token: %s", err)
			ctx.Error = "Internal error, please try again"
			WriteHTMLTemplate(500, h.template, ctx, w)
			return
		}

		ctx.NewAccessToken = token
		ctx.AccessTokens = append(ctx.AccessTokens, AccessToken{tokenID, tokenName, nil})
	}

	// Expire sessions
	expireSessions, found := GetFormCheckboxes("expire", req.Form)
	if found && len(expireSessions) > 0 && expireSessions[0] == "expireAllSessions" {
		if err := h.store.ExpireAllSessions(loginName); err != nil {
			ctx.Error = "Internal error, please try again"
			WriteHTMLTemplate(500, h.template, ctx, w)
			return
		}

	}

	// All ok, redirect to /me
	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)
	http.Redirect(w, req, "/me", 302)

}
