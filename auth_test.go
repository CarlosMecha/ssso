package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type authorizeCase struct {
	sql          [][]interface{}
	req          *http.Request
	expectedCode int
	expectedUser string
}

func TestServeHTTP_authorize(t *testing.T) {
	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := make([]authorizeCase, 0)

	// OK (access token)
	req1, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req1.Header["X-Auth-Access-Token"] = []string{createTestToken(store, "test_1", "12345678", t)}
	cases = append(cases, authorizeCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1000, 'test_1', 'test', '12345678')"},
		},
		req:          req1,
		expectedCode: 200,
		expectedUser: "test_1",
	})

	// OK (session)
	req2, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header["X-Auth-Cookie-Token"] = []string{createTestSession(store, "test_2", "12345678", "test_agent", t)}
	cases = append(cases, authorizeCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_2', 'test 2', '2@test.com', $1)", hashTestPassword(store, "12345", t)},
			[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_2', 'test_agent', '12345678', '2025-01-01'::TIMESTAMP)"},
		},
		req:          req2,
		expectedCode: 200,
		expectedUser: "test_2",
	})

	// Invalid access token
	req3, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req3.Header["X-Auth-Access-Token"] = []string{"123212312 31 2312 3123"}
	cases = append(cases, authorizeCase{req: req3, expectedCode: 401})

	// Invalid session
	req4, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req4.Header["X-Auth-Cookie-Token"] = []string{"123212312 31 2312 3123"}
	cases = append(cases, authorizeCase{req: req4, expectedCode: 401})

	// Missing access token
	req5, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req5.Header["X-Auth-Access-Token"] = []string{createTestToken(store, "test_1", "abcdefgh", t)}
	cases = append(cases, authorizeCase{req: req5, expectedCode: 401})

	// Missing session
	req6, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req6.Header["X-Auth-Cookie-Token"] = []string{createTestSession(store, "test_2", "abcdefgh", "test_agent", t)}
	cases = append(cases, authorizeCase{req: req6, expectedCode: 401})

	// Revoked access token
	req7, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req7.Header["X-Auth-Access-Token"] = []string{createTestToken(store, "test_1", "ABCDEFGH", t)}
	cases = append(cases, authorizeCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, revoked) VALUES (1002, 'test_1', 'test_revoked', 'ABCDEFGH', TRUE)"},
		},
		req:          req7,
		expectedCode: 401,
	})

	// Expired session
	req8, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req8.Header["X-Auth-Cookie-Token"] = []string{createTestToken(store, "test_2", "ABCDEFGH", t)}
	cases = append(cases, authorizeCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1003, 'test_2', 'test_expired', 'ABCDEFGH', '2001-01-01'::TIMESTAMP)"},
		},
		req:          req8,
		expectedCode: 401,
	})

	// No auth
	req9, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, authorizeCase{req: req9, expectedCode: 403})

	// POST
	req10, err := http.NewRequest("POST", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, authorizeCase{req: req10, expectedCode: 404})

	handler := AuthHandler{store: store}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, test.req)

		if recorder.Code != test.expectedCode {
			t.Errorf("[Test %d] Expected code %d got %d", i, test.expectedCode, recorder.Code)
		}

		if auth, found := recorder.HeaderMap["X-Auth-User"]; recorder.Code == 200 && found && len(auth) > 0 {
			if auth[0] != test.expectedUser {
				t.Errorf("[Test %d] Expected user %s got %s", i, test.expectedUser, auth[0])
			}
		}

	}
}
