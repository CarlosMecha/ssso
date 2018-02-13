package main

import (
	"context"
	"testing"
	"time"
)

const (
	TestHost      = "localhost"
	TestPort      = uint16(5432)
	TestDatabase  = "postgres"
	TestUsername  = "postgres"
	TestPassword  = ""
	TestBase64Key = "5247DBA0A29CBBBF9DED3C907B7E0DE9"
)

func getTestStore(t *testing.T) *Store {
	config := StoreConfiguration{
		Host:      TestHost,
		Port:      TestPort,
		Database:  TestDatabase,
		Username:  TestUsername,
		Password:  TestPassword,
		Base64Key: TestBase64Key,
	}

	store, err := NewStore(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestNewStore(t *testing.T) {
	getTestStore(t).Close()
}

func TestAuthenticateAccessToken(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql                   [][]interface{}
		token                 string
		expectedAuthorization Authorization
		expectedError         error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1000, 'test_1', 'test', '12345678')"},
			},
			token: createTestToken(store, "test_1", "12345678", t),
			expectedAuthorization: Authorization{LoginName: "test_1", Email: "1@test.com"},
		},
		// Invalid token
		{
			token:         "123212312 31 2312 3123",
			expectedError: ErrTokenInvalid,
		},
		// Missing token
		{
			token:         createTestToken(store, "test_1", "abcdefgh", t),
			expectedError: ErrTokenInvalid,
		},
		// Revoked token
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, revoked) VALUES (1001, 'test_1', 'test_revoked', 'ABCDEFGH', TRUE)"},
			},
			token:         createTestToken(store, "test_1", "ABCDEFGH", t),
			expectedError: ErrTokenRevoked,
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if auth, err := store.AuthenticateAccessToken(test.token); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		} else if auth.LoginName != test.expectedAuthorization.LoginName || auth.Email != test.expectedAuthorization.Email {
			t.Errorf("[Test %d] expected auth %s:%s, got %s:%s", i, test.expectedAuthorization.LoginName, test.expectedAuthorization.Email, auth.LoginName, auth.Email)
		}
	}
}

func TestCreateAccessToken(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		tokenName     string
		loginName     string
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
			},
			tokenName: "token_1",
			loginName: "test_1",
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if _, _, err := store.CreateAccessToken(test.loginName, test.tokenName); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func TestRevokeAccessToken(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		id            int
		loginName     string
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1000, 'test_1', 'test', '12345678')"},
			},
			id:        1000,
			loginName: "test_1",
		},
		// Missing token
		{
			id:            1001,
			loginName:     "test_1",
			expectedError: ErrTokenInvalid,
		},
		// Revoked token
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, revoked) VALUES (1002, 'test_1', 'test_revoked', 'ABCDEFGH', TRUE)"},
			},
			id:        1002,
			loginName: "test_1",
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if err := store.RevokeAccessToken(test.loginName, test.id); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func TestExpireAllSessions(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		loginName     string
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1000, 'test_1', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_1', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1002, 'test_1', 'test', '12345678', '2025-01-01'::TIMESTAMP)"},
			},
			loginName: "test_1",
		},
		// No sessions
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_2', 'test 2', '2@test.com', $1)", hashTestPassword(store, "12345", t)},
			},
			loginName: "test_2",
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if err := store.ExpireAllSessions(test.loginName); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func TestAuthenticateSessions(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql                   [][]interface{}
		session               string
		expectedAuthorization Authorization
		expectedError         error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1000, 'test_1', 'test_agent', '12345678', '2025-01-01'::TIMESTAMP)"},
			},
			session:               createTestSession(store, "test_1", "12345678", "test_agent", t),
			expectedAuthorization: Authorization{LoginName: "test_1", Email: "1@test.com"},
		},
		// Invalid session
		{
			session:       "123212312 31 2312 3123",
			expectedError: ErrSessionInvalid,
		},
		// Missing session
		{
			session:       createTestSession(store, "test_1", "abcdefgh", "test_agent", t),
			expectedError: ErrSessionInvalid,
		},
		// Expired session
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_1', 'test_expired', 'ABCDEFGH', '2001-01-01'::TIMESTAMP)"},
			},
			session:       createTestSession(store, "test_1", "ABCDEFGH", "test_expired", t),
			expectedError: ErrSessionExpired,
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if auth, err := store.AuthenticateSession(test.session); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		} else if auth.LoginName != test.expectedAuthorization.LoginName || auth.Email != test.expectedAuthorization.Email {
			t.Errorf("[Test %d] expected auth %s:%s, got %s:%s", i, test.expectedAuthorization.LoginName, test.expectedAuthorization.Email, auth.LoginName, auth.Email)
		}
	}
}

func TestValidateCredentials(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		creds         Credentials
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
			},
			creds: Credentials{loginName: "test_1", password: "12345", agent: "test_agent", expire: 15 * 24 * time.Hour},
		},
		// Invalid password
		{
			creds:         Credentials{loginName: "test_1", password: "1", agent: "test_agent", expire: 15 * 24 * time.Hour},
			expectedError: ErrInvalidCredentials,
		},
		// Invalid login
		{
			creds:         Credentials{loginName: "test_2", password: "12345", agent: "test_agent", expire: 15 * 24 * time.Hour},
			expectedError: ErrInvalidCredentials,
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if err := store.ValidateCredentials(test.creds); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func TestLogin(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		creds         Credentials
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
			},
			creds: Credentials{loginName: "test_1", password: "12345", agent: "test_agent", expire: 15 * 24 * time.Hour},
		},
		// Invalid password
		{
			creds:         Credentials{loginName: "test_1", password: "1", agent: "test_agent", expire: 15 * 24 * time.Hour},
			expectedError: ErrInvalidCredentials,
		},
		// Invalid login
		{
			creds:         Credentials{loginName: "test_2", password: "12345", agent: "test_agent", expire: 15 * 24 * time.Hour},
			expectedError: ErrInvalidCredentials,
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if _, err := store.Login(test.creds); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func TestGetUser(t *testing.T) {

	store := getTestStore(t)
	defer store.Close()
	clean(store, t)

	cases := []struct {
		sql           [][]interface{}
		loginName     string
		expectedError error
	}{
		// OK
		{
			sql: [][]interface{}{
				[]interface{}{"INSERT INTO users (login_name, name, email, password) VALUES ('test_1', 'test 1', '1@test.com', $1)", hashTestPassword(store, "12345", t)},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret) VALUES (1000, 'test_1', 'test', '12345678')"},
				[]interface{}{"INSERT INTO access_tokens (id, login_name, name, secret, revoked) VALUES (1001, 'test_1', 'test', 'ABCDEFG', TRUE)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1000, 'test_1', 'test_agent', '12345678', '2025-01-01'::TIMESTAMP)"},
				[]interface{}{"INSERT INTO sessions (id, login_name, agent, secret, expires_on) VALUES (1001, 'test_1', 'test_agent', '12345678', '2001-01-01'::TIMESTAMP)"},
			},
			loginName: "test_1",
		},
	}

	for i, test := range cases {
		executeStatements(store, test.sql, t)

		if _, err := store.GetUser(test.loginName); err != nil {
			if test.expectedError == nil {
				t.Errorf("[Test %d] unexpected error %s", i, err.Error())
			} else if err != test.expectedError {
				t.Errorf("[Test %d] expected error %s, got %s", i, test.expectedError.Error(), err.Error())
			}
		} else if test.expectedError != nil {
			t.Errorf("[Test %d] expected error %s", i, test.expectedError.Error())
		}
	}
}

func executeStatements(store *Store, stmts [][]interface{}, t *testing.T) {

	conn, err := store.pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer store.pool.Release(conn)

	for _, stmt := range stmts {
		sql := stmt[0].(string)
		if _, err := conn.Exec(sql, stmt[1:]...); err != nil {
			t.Fatalf("Error for statement '%s': %s", stmt, err)
		}
	}
}

func clean(store *Store, t *testing.T) {
	conn, err := store.pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer store.pool.Release(conn)

	for _, table := range []string{"access_tokens, sessions, users"} {
		conn.Exec("TRUNCATE TABLE " + table)
	}
}

func createTestToken(store *Store, loginName, secret string, t *testing.T) string {
	paddedLoginName := pad(loginName, loginNameSize)

	accessToken, err := store.encrypt(paddedLoginName + secret)
	if err != nil {
		t.Fatal(err)
	}

	return accessToken
}

func hashTestPassword(store *Store, password string, t *testing.T) []byte {
	hash, err := store.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func createTestSession(store *Store, loginName, secret, agent string, t *testing.T) string {
	paddedLoginName := pad(loginName, loginNameSize)
	paddedAgent := pad(agent, agentSize)

	accessToken, err := store.encrypt(paddedLoginName + secret + paddedAgent)
	if err != nil {
		t.Fatal(err)
	}

	return accessToken
}
