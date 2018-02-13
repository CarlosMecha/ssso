package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const meHTML = `
<html>
	<head>
		<title>SSSO</title>
	</head>
	<body>
		<h1>Hi {{.Name}}!</h1>

		<form action="/logout" method="post">
			<button type="submit">Logout</button>	
		</form>

		<form action="/me" method="post">
			<h3>Settings</h3>
			<div>	
				<label for="loginNameInput">Login Name:</label><input type="text" id="loginNameInput" name="loginName" value="{{.LoginName}}" disabled></input>
				<br/>
				<label for="passwordInput">Current Password:</label><input type="text" id="passwordInput" name="password"></input>
				<label for="newPasswordInput">New Password:</label><input type="text" id="newPasswordInput" name="newPassword"></input>
				<label for="repeatPasswordInput">Repeat New Password:</label><input type="text" id="repeatPasswordInput" name="repeatPassword"></input>

				{{if .PasswordUpdated}}
					<strong>Password updated</strong>
				{{end}}
			</div>

			<h3>Personal access tokens</h3>
			{{with .AccessTokens}}
			<table>
				<tr><th>Name</th><th>Last Used</th><th>Revoke</th></tr>
				{{range $i, $token := .}}
				<tr>
					<td>{{$token.Name}}</td>
					{{if $token.LastUsed}}
						<td>{{.LastUsed}}</td>
					{{else}}
						<td>Never</td>
					{{end}}
					<td><input type="checkbox" name="revoke" value="{{.ID}}"/></td>
				</tr>
				{{end}}
			</table>
			{{end}}

			<div>
				<label for="newTokenName">New token name: </label><input type="text" id="newTokenName" name="name" value=""/>
			</div>

			{{if .NewAccessToken}}
				<p><strong>New access token, please keep it secret: {{.NewAccessToken}}</strong></p>
			{{end}}

			<h3>Sessions</h3>
			{{with .Sessions}}
			<table>
				<tr><th>Agent</th></tr>
				{{range $i, $session := .}}
				<tr><td>{{$session.Agent}}</td></tr>
				{{end}}
			</table>
			{{end}}
			
			{{if .Sessions}}
				<label for="expireCheckbox">Expire all sessions</label><input type="checkbox" id="expireCheckbox" name="expire" value="expireAllSessions"></input> 
			{{end}}

			{{if .Error}}
				<p><strong>{{.Error}}</strong></p>
			{{end}}
			<br/>
			<br/>
			<button type="submit">Save</button>	
		</form>
	</body>
</html>
`

// MeHandler handles personal pages requests
type MeHandler struct {
	store *Store
}

// MeContext is the context for the me.html page
type MeContext struct {
	Error           string
	PasswordUpdated string
	NewAccessToken  string
	User
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println("Me")

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
		w.WriteHeader(401)
		return
	} else if err != nil {
		log.Fatalf("Unable to retrieve user: %s\n", err.Error())
		w.WriteHeader(500)
		return
	}

	ctx := MeContext{User: user}

	if req.Method == http.MethodGet {
		if v, found := req.Header["Accept"]; found && len(v) == 1 && strings.Contains(v[0], "json") {
			w.Header()["Content-Type"] = []string{"application/json; charset=utf-8"}
			encoder := json.NewEncoder(w)
			if err := encoder.Encode(user); err != nil {
				log.Fatalf("Unable to marshal user: %s\n", err.Error())
				w.WriteHeader(500)
			}
		} else {
			writeMePage(200, ctx, w)
		}
		return
	}

	if err := req.ParseForm(); err != nil {
		log.Printf("ERROR parsing form: %s\n", err.Error())
		ctx.Error = "Error submitting the form, please try again"
		writeMePage(400, ctx, w)
		return
	}

	// Update password
	newPassword, foundNewPassword := GetFormString("newPassword", req.Form)
	repeatPassword, foundRepeatPassword := GetFormString("repeatPassword", req.Form)
	if (foundNewPassword || foundRepeatPassword) && (newPassword != "" || repeatPassword != "") {
		if newPassword != repeatPassword {
			ctx.Error = "The new password does not match"
			writeMePage(400, ctx, w)
		} else if len(newPassword) < 8 || len(newPassword) > 64 {
			ctx.Error = "Invalid new password, introduce a new password between 8 to 64 characters"
			writeMePage(400, ctx, w)
		}

		password, found := GetFormString("password", req.Form)
		if !found || password == "" {
			ctx.Error = "Please introduce your current password"
			writeMePage(400, ctx, w)
		}

		if err := h.store.ValidateCredentials(Credentials{loginName: loginName, password: password}); err != nil {
			ctx.Error = "Invalid password"
			writeMePage(400, ctx, w)
		}

		if err := h.store.UpdatePassword(loginName, newPassword); err != nil {
			ctx.Error = "Error storing new password, pease try again"
			writeMePage(500, ctx, w)
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
				writeMePage(400, ctx, w)
				return
			}

			if err := h.store.RevokeAccessToken(loginName, tokenID); err != nil && err != ErrTokenInvalid {
				log.Printf("Error revoking token: %s", err)
				ctx.Error = "Internal error, please try again"
				writeMePage(500, ctx, w)
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
			log.Printf("Error creating token: %s", err)
			ctx.Error = "Internal error, please try again"
			writeMePage(500, ctx, w)
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
			writeMePage(500, ctx, w)
			return
		}

	}

	// All ok, redirect to /me
	http.Redirect(w, req, "/me", 302)

}

func writeMePage(code int, ctx MeContext, w http.ResponseWriter) {
	WriteHTMLTemplate(code, "me.html", meHTML, ctx, w)
}
