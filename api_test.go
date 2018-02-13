package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServeHTTP_apiUsers(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	now := time.Now()

	cases := []struct {
		sql          [][]interface{}
		path         string
		expectedCode int
		expectedUser User
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, last_used) VALUES (1000, 'test_1', 'test', '12345678', $1)", now},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, revoked) VALUES (1001, 'test_1', 'test', 'ABCDEFG', TRUE)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1000, 'test_1', 'test_agent', '12345678', '2025-01-01'::TIMESTAMP)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_1', 'test_agent', '12345678', '2001-01-01'::TIMESTAMP)"},
			},
			path:         "/api/users/test_1",
			expectedCode: 200,
			expectedUser: User{
				LoginName:    "test_1",
				Name:         "test 1",
				Email:        "1@test.com",
				AccessTokens: []AccessToken{{ID: 1000, Name: "test", LastUsed: &now}},
				Sessions:     []Session{{Agent: "test_agent"}},
			},
		},
		// Missing user
		{
			path:         "/api/users/i_dont_exist",
			expectedCode: 401,
		},
	}

	handler := APIHandler{store: store}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		recorder := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, test.path, nil)
		if err != nil {
			t.Fatal(err)
		}

		handler.ServeHTTP(recorder, req)

		if recorder.Code != test.expectedCode {
			t.Errorf("[Test %d] Expected code %d got %d", i, test.expectedCode, recorder.Code)
			continue
		}

		if recorder.Code == 200 {
			var got User
			if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}

			if got.LoginName != test.expectedUser.LoginName || got.Name != test.expectedUser.Name || got.Email != test.expectedUser.Email {
				t.Errorf("[Test %d] Expected user %v got %v", i, test.expectedUser, got)
				continue
			}

			if len(got.AccessTokens) != len(test.expectedUser.AccessTokens) {
				t.Errorf("[Test %d] Expected access tokens %v got %v", i, test.expectedUser.AccessTokens, got.AccessTokens)
				continue
			}

			if len(got.Sessions) != len(test.expectedUser.Sessions) {
				t.Errorf("[Test %d] Expected sessions %v got %v", i, test.expectedUser.Sessions, got.Sessions)
				continue
			}
		}

	}

}
