package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/jackc/pgx"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	loginNameSize = 20
	secretSize    = 8
	agentSize     = 100
)

var (
	// ErrUserNotFound when the user is not in the database
	ErrUserNotFound = errors.New("not found")
	// ErrInvalidCredentials when one or more credentials don't match
	// or have an unknown format.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrSessionInvalid when the session doesn't match the stored ones.
	ErrSessionInvalid = errors.New("session invalid")
	// ErrTokenInvalid when the access token doesn't match the stored ones.
	ErrTokenInvalid = errors.New("token is invalid")
	// ErrSessionExpired when the session has expired.
	ErrSessionExpired = errors.New("session expired")
	// ErrTokenRevoked when the access token has been revoked by the user.
	ErrTokenRevoked = errors.New("access token revoked")
	// ErrPasswordTooLong when the password is bigger that what BCrypt allow.
	ErrPasswordTooLong = errors.New("password too long")
)

// Store handles all DB interaction
type Store struct {
	block cipher.Block
	pool  *pgx.ConnPool
}

// Authorization contains the user identification after
// a successful authentication
type Authorization struct {
	LoginName string
	Email     string
	Name      string
}

// StoreConfiguration describes the store
type StoreConfiguration struct {
	Host      string
	Port      uint16
	Username  string
	Password  string
	Database  string
	Base64Key string
}

// Credentials are the access credentials
type Credentials struct {
	agent     string
	loginName string
	password  string
	expire    time.Duration
}

// User is a database user record.
type User struct {
	LoginName    string
	Name         string
	Email        string
	Sessions     []Session
	AccessTokens []AccessToken
}

// Session describes a opened session
type Session struct {
	Agent string
}

// AccessToken describes an access token
type AccessToken struct {
	ID       int
	Name     string
	LastUsed *time.Time
}

// NewStore creates a Store using a PG backend
func NewStore(ctx context.Context, cfg StoreConfiguration) (*Store, error) {

	key, err := base64.StdEncoding.DecodeString(cfg.Base64Key)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		ConnConfig: pgx.ConnConfig{
			Host:     cfg.Host,
			Port:     cfg.Port,
			User:     cfg.Username,
			Password: cfg.Password,
			Database: cfg.Database,
		},
	})
	if err != nil {
		return nil, err
	}

	conn, err := pool.Acquire()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}

	return &Store{
		pool:  pool,
		block: block,
	}, nil
}

// AuthenticateAccessToken returns the authorization if the token is valid
// and not revoked.
func (s *Store) AuthenticateAccessToken(token string) (Authorization, error) {

	data, err := s.decrypt(token)
	if err != nil || len(data) != loginNameSize+secretSize {
		return Authorization{}, ErrTokenInvalid
	}

	loginName := strings.Trim(data[:loginNameSize], " ")
	secret := data[loginNameSize:]

	var id int
	var lastUsed *time.Time
	var revoked bool
	row := s.pool.QueryRow("SELECT id, last_used, revoked FROM access_tokens WHERE login_name = $1 AND secret = $2", loginName, secret)
	if err := row.Scan(&id, &lastUsed, &revoked); err != nil {
		if err == pgx.ErrNoRows {
			return Authorization{}, ErrTokenInvalid
		}
		return Authorization{}, err
	}

	if revoked {
		return Authorization{}, ErrTokenRevoked
	}

	auth := Authorization{LoginName: loginName}
	row = s.pool.QueryRow("SELECT email, name FROM users WHERE login_name = $1", loginName)
	if err := row.Scan(&auth.Email, &auth.Name); err != nil {
		if err == pgx.ErrNoRows {
			logrus.Warnf("Access tokens for missing user %s", loginName)
			return Authorization{}, ErrTokenInvalid
		}
		return Authorization{}, err
	}

	if lastUsed == nil || time.Now().Sub(*lastUsed) > 24*time.Hour {
		if _, err := s.pool.Exec("UPDATE access_tokens SET last_used = NOW() WHERE id = $1", id); err != nil {
			return Authorization{}, err
		}
	}

	return auth, nil
}

// CreateAccessToken generates a new access token. It returns the id of the token
// and the token itself
func (s *Store) CreateAccessToken(loginName, tokenName string) (int, string, error) {

	secret := uniuri.NewLen(secretSize)
	stmt := "INSERT INTO access_tokens (login_name, name, secret) VALUES ($1, $2, $3) RETURNING id"
	row := s.pool.QueryRow(stmt, loginName, tokenName, secret)
	var id int
	if err := row.Scan(&id); err != nil {
		return 0, "", err
	}

	paddedLoginName := pad(loginName, loginNameSize)

	accessToken, err := s.encrypt(paddedLoginName + secret)
	if err != nil {
		return 0, "", err
	}

	return id, accessToken, nil

}

// RevokeAccessToken invalidates a token. It can't be used anymore.
func (s *Store) RevokeAccessToken(loginName string, id int) error {

	tag, err := s.pool.Exec("UPDATE access_tokens SET revoked = TRUE, revoked_on = NOW() WHERE id = $1 AND login_name = $2", id, loginName)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return ErrTokenInvalid
	}

	return nil
}

// ExpireAllSessions expires all activated sessions for the user.
func (s *Store) ExpireAllSessions(loginName string) error {
	_, err := s.pool.Exec("UPDATE sessions SET expires_on = '1970-01-01'::TIMESTAMP WHERE login_name = $1", loginName)
	return err
}

// AuthenticateSession validates the cookie session.
func (s *Store) AuthenticateSession(cookieValue string) (Authorization, error) {

	data, err := s.decrypt(cookieValue)
	if err != nil || len(data) != loginNameSize+secretSize+agentSize {
		logrus.Errorf("Invalid data size (%d) or error %v: %s", len(data), err, data)
		return Authorization{}, ErrSessionInvalid
	}

	loginName := strings.Trim(data[:loginNameSize], " ")
	secret := data[loginNameSize : loginNameSize+secretSize]
	agent := strings.Trim(data[loginNameSize+secretSize:], " ")

	var id int
	var expiresOn time.Time
	row := s.pool.QueryRow("SELECT id, expires_on FROM sessions WHERE login_name = $1 AND secret = $2 AND agent = $3", loginName, secret, agent)
	if err := row.Scan(&id, &expiresOn); err != nil {
		if err == pgx.ErrNoRows {
			logrus.Debug("No rows returned for session")
			return Authorization{}, ErrSessionInvalid
		}
		return Authorization{}, err
	}

	if expiresOn.IsZero() || expiresOn.Before(time.Now()) {
		return Authorization{}, ErrSessionExpired
	}

	auth := Authorization{LoginName: loginName}
	row = s.pool.QueryRow("SELECT email, name FROM users WHERE login_name = $1", loginName)
	if err := row.Scan(&auth.Email, &auth.Name); err != nil {
		if err == pgx.ErrNoRows {
			logrus.Warnf("Sessions for missing user %s", loginName)
			return Authorization{}, ErrSessionInvalid
		}
		return Authorization{}, err
	}

	return auth, nil
}

// Login validates the credentials and returns the cookie session value.
func (s *Store) Login(cred Credentials) (string, error) {

	if err := s.ValidateCredentials(cred); err != nil {
		return "", err
	}

	secret := uniuri.NewLen(secretSize)
	if len(cred.agent) > agentSize {
		cred.agent = cred.agent[:agentSize]
	}

	stmt := "INSERT INTO sessions (login_name, agent, secret, expires_on) VALUES ($1, $2, $3, $4)"
	if _, err := s.pool.Exec(stmt, cred.loginName, cred.agent, secret, time.Now().Add(cred.expire)); err != nil {
		return "", err
	}

	paddedLoginName := pad(cred.loginName, loginNameSize)
	paddedAgent := pad(cred.agent, agentSize)

	return s.encrypt(paddedLoginName + secret + paddedAgent)

}

// ValidateCredentials return an error if the credentials are invalid
func (s *Store) ValidateCredentials(cred Credentials) error {
	password := new([]byte)
	row := s.pool.QueryRow("SELECT password FROM users WHERE login_name = $1", cred.loginName)
	if err := row.Scan(&password); err != nil {
		if err == pgx.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	err := bcrypt.CompareHashAndPassword(*password, []byte(cred.password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return ErrInvalidCredentials
	}

	return err
}

// UpdatePassword changes the current password for the provided one
func (s *Store) UpdatePassword(loginName, newPassword string) error {
	hash, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec("UPDATE users SET password = $1 WHERE login_name = $2", hash, loginName)
	return err
}

// GetUser returns the user information.
func (s *Store) GetUser(loginName string) (User, error) {

	user := User{LoginName: loginName}
	row := s.pool.QueryRow("SELECT name, email FROM users WHERE login_name = $1", loginName)
	if err := row.Scan(&user.Name, &user.Email); err != nil {
		if err == pgx.ErrNoRows {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	sessionRows, err := s.pool.Query("SELECT agent FROM sessions WHERE login_name = $1 AND expires_on > NOW() ORDER BY created_on", loginName)
	if err != nil {
		return User{}, err
	}
	defer sessionRows.Close()

	user.Sessions = make([]Session, 0)
	for sessionRows.Next() {
		var session Session
		if err := sessionRows.Scan(&session.Agent); err != nil {
			return User{}, err
		}
		user.Sessions = append(user.Sessions, session)
	}
	if err := sessionRows.Err(); err != nil {
		return User{}, err
	}

	accessTokenRows, err := s.pool.Query("SELECT id, name, last_used FROM access_tokens WHERE login_name = $1 AND revoked IS FALSE ORDER BY created_on", loginName)
	if err != nil {
		return User{}, err
	}
	defer accessTokenRows.Close()

	user.AccessTokens = make([]AccessToken, 0)

	for accessTokenRows.Next() {
		var accessToken AccessToken
		if err := accessTokenRows.Scan(&accessToken.ID, &accessToken.Name, &accessToken.LastUsed); err != nil {
			return User{}, err
		}
		user.AccessTokens = append(user.AccessTokens, accessToken)
	}
	if err := accessTokenRows.Err(); err != nil {
		return User{}, err
	}

	return user, nil
}

// Close closes the underlying connection pool
func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) encrypt(text string) (string, error) {

	// VI+text
	cipherText := make([]byte, aes.BlockSize+len(text))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cipher.NewCFBEncrypter(s.block, iv).XORKeyStream(cipherText[aes.BlockSize:], []byte(text))

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func (s *Store) decrypt(encodedText string) (string, error) {

	data, err := base64.URLEncoding.DecodeString(encodedText)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", errors.New("invalid encoded text")
	}

	iv := data[:aes.BlockSize]
	cipherText := data[aes.BlockSize:]

	cipher.NewCFBDecrypter(s.block, iv).XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// HashPassword returns the hash to be stored in the database. No
// plaintext passwords for us.
func (s *Store) HashPassword(password string) ([]byte, error) {
	content := []byte(password)
	// I wasn't able to confirm the hard 72 limit
	if len(content) > 72 {
		return nil, ErrPasswordTooLong
	}

	return bcrypt.GenerateFromPassword(content, bcrypt.DefaultCost)
}

func pad(text string, size int) string {
	if len(text) > size {
		return text[:size]
	}

	paddedText := text
	for len(paddedText) < size {
		paddedText += " "
	}
	return paddedText
}
