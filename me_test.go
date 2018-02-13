package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type meCase struct {
	sql          [][]interface{}
	req          *http.Request
	expectedCode int
}

func TestServeHTTP_me(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := make([]meCase, 0)

	// No user
	req0, err := http.NewRequest("GET", "/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, meCase{req: req0, expectedCode: 401})

	// No user in DB
	req1, err := http.NewRequest("GET", "/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req1.Header["X-Auth-User"] = []string{"i_dont_exist"}
	cases = append(cases, meCase{req: req1, expectedCode: 401})

	// GET html OK
	req2, err := http.NewRequest("GET", "/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header["X-Auth-User"] = []string{"test_1"}
	cases = append(cases, meCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
		},
		req:          req2,
		expectedCode: 200,
	})

	// GET json OK
	req3, err := http.NewRequest("GET", "/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req3.Header["X-Auth-User"] = []string{"test_1"}
	req3.Header["Accept"] = []string{"application/json"}
	cases = append(cases, meCase{req: req3, expectedCode: 200})

	// Update password OK
	req4, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"password":       []string{"12345"},
		"newPassword":    []string{"67890abcde"},
		"repeatPassword": []string{"67890abcde"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req4.Header["X-Auth-User"] = []string{"test_2"}
	cases = append(cases, meCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_2', 'test 2', '2@test.com', $1)", hashTestPassword(store, "12345", t)},
		},
		req:          req4,
		expectedCode: 200,
	})

	// Update password, invalid current password
	req5, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"password":       []string{"11111"},
		"newPassword":    []string{"67890abcde"},
		"repeatPassword": []string{"67890abcde"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req5.Header["X-Auth-User"] = []string{"test_2"}
	cases = append(cases, meCase{req: req5, expectedCode: 400})

	// Update password, repeat password does not match password
	req6, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"password":       []string{"12345"},
		"newPassword":    []string{"67890abcde"},
		"repeatPassword": []string{"67890abcde1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req6.Header["X-Auth-User"] = []string{"test_2"}
	cases = append(cases, meCase{req: req6, expectedCode: 400})

	// Revoke access tokens
	req7, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"revoke": []string{"1001", "1003"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req7.Header["X-Auth-User"] = []string{"test_3"}
	cases = append(cases, meCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_3', 'test 3', '3@test.com', $1)", hashTestPassword(store, "12345", t)},
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1001, 'test_3', 'test', '12345678')"},
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1002, 'test_3', 'test', '12345678')"},
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1003, 'test_3', 'test', '12345678')"},
		},
		req:          req7,
		expectedCode: 200,
	})

	// New access token
	req8, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"name": []string{"new_access_token"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req8.Header["X-Auth-User"] = []string{"test_4"}
	cases = append(cases, meCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_4', 'test 4', '4@test.com', $1)", hashTestPassword(store, "12345", t)},
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1004, 'test_4', 'test', '12345678')"},
		},
		req:          req8,
		expectedCode: 200,
	})

	// Expire sessions
	req9, err := http.NewRequest("POST", "/me", formToReader(map[string][]string{
		"expire": []string{"expireAllSessions"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	req9.Header["X-Auth-User"] = []string{"test_5"}
	cases = append(cases, meCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_5', 'test 5', '5@test.com', $1)", hashTestPassword(store, "12345", t)},
			[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1000, 'test_5', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
			[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_5', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
			[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1002, 'test_5', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
		},
		req:          req9,
		expectedCode: 200,
	})

	handler := MeHandler{store: store}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if test.req.Method == http.MethodPost {
			test.req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		}

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, test.req)

		if recorder.Code != test.expectedCode {
			t.Errorf("[Test %d] Expected code %d got %d", i, test.expectedCode, recorder.Code)
		}

	}

}
