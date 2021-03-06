package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// APIHandler handles the REST API, make sure all these endpoints are
// secured and just accessible from the internal network.
type APIHandler struct {
	store *Store
}

func (h *APIHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Requesting %s %s", req.Method, req.URL.Path)

	if !strings.HasPrefix(req.URL.Path, "/api/users/") || req.Method != http.MethodGet {
		w.WriteHeader(404)
		return
	}

	loginName := strings.Replace(req.URL.Path, "/api/users/", "", 1)

	user, err := h.store.GetUser(loginName)
	if err == ErrUserNotFound {
		w.WriteHeader(401)
		return
	} else if err != nil {
		logrus.Errorf("Unable to retrieve user: %s", err.Error())
		w.WriteHeader(500)
		return
	}

	w.Header()["Content-Type"] = []string{"application/json; charset=utf-8"}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		logrus.Errorf("Unable to marshal user: %s", err.Error())
		w.WriteHeader(500)
	}

	logrus.Debugf("Request to %s %s completed", req.Method, req.URL.Path)
}
