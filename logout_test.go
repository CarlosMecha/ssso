package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type logoutCase struct {
	req                   *http.Request
	expectedCode          int
	expectedExpiredCookie bool
}

func TestServeHTTP_logout(t *testing.T) {

	cases := make([]logoutCase, 0)

	// OK
	req1, err := http.NewRequest("POST", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	req1.AddCookie(&http.Cookie{
		Name:    "ssso-session",
		Expires: time.Now().AddDate(0, 0, 2),
	})
	cases = append(cases, logoutCase{
		req:                   req1,
		expectedCode:          302,
		expectedExpiredCookie: true,
	})

	// No cookie
	req2, err := http.NewRequest("POST", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, logoutCase{req: req2, expectedCode: 302})

	// GET
	req3, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, logoutCase{req: req3, expectedCode: 404})

	handler := LogoutHandler{}

	for i, test := range cases {

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, test.req)

		if recorder.Code != test.expectedCode {
			t.Errorf("[Test %d] Expected code %d got %d", i, test.expectedCode, recorder.Code)
		}

		if test.expectedExpiredCookie {
			if cookie, found := recorder.HeaderMap["Set-Cookie"]; !found {
				t.Errorf("[Test %d] Expected expired cookie, missing", i)
			} else {
				t.Log(cookie)
			}
		}

	}
}
