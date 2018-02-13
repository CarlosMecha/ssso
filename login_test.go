package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type loginCase struct {
	sql          [][]interface{}
	req          *http.Request
	expectedCode int
}

func TestServeHTTP_login(t *testing.T) {
	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := make([]loginCase, 0)

	// GET
	req1, err := http.NewRequest("GET", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{req: req1, expectedCode: 200})

	// OK
	req2, err := http.NewRequest("POST", "/login", formToReader(map[string][]string{
		"loginname": []string{"test_1"},
		"password":  []string{"12345"},
		"remember":  []string{""},
	}))
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{
		sql: [][]interface{}{
			[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
		},
		req:          req2,
		expectedCode: 302,
	})

	// OK (remember)
	req3, err := http.NewRequest("POST", "/login", formToReader(map[string][]string{
		"loginname": []string{"test_1"},
		"password":  []string{"12345"},
		"remember":  []string{"remember"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{
		req:          req3,
		expectedCode: 302,
	})

	// Invalid credentials
	req4, err := http.NewRequest("POST", "/login", formToReader(map[string][]string{
		"loginname": []string{"test_1"},
		"password":  []string{"1234567890"},
		"remember":  []string{""},
	}))
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{
		req:          req4,
		expectedCode: 401,
	})

	// Missing credentials
	req5, err := http.NewRequest("POST", "/login", formToReader(map[string][]string{
		"loginname": []string{"test_1"},
		"remember":  []string{""},
	}))
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{
		req:          req5,
		expectedCode: 401,
	})

	// PUT
	req6, err := http.NewRequest("PUT", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, loginCase{req: req6, expectedCode: 404})

	handler := NewLoginHandler(store, "test.com", "login.html")

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		test.req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, test.req)

		if recorder.Code != test.expectedCode {
			t.Errorf("[Test %d] Expected code %d got %d", i, test.expectedCode, recorder.Code)
		}

		if test.expectedCode == 200 && test.req.Method == http.MethodPost && recorder.Code == 200 {
			if _, found := recorder.HeaderMap["Set-Cookie"]; !found {
				t.Errorf("[Test %d] Expected cookie, missing", i)
			}
		}

	}
}

func formToReader(form url.Values) io.Reader {
	return bytes.NewReader([]byte(form.Encode()))
}
