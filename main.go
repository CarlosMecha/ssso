package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// Getenv returns the value of the environment variable if is not
// empty. The default value otherwise.
func Getenv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// insertUser inserts a new user in the database.
func insertUser(store *Store) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter login name: ")
	loginName, _ := reader.ReadString('\n')
	loginName = strings.Replace(loginName, "\n", "", 1)

	fmt.Print("Enter name: ")
	name, _ := reader.ReadString('\n')
	name = strings.Replace(name, "\n", "", 1)

	fmt.Print("Enter email: ")
	email, _ := reader.ReadString('\n')
	email = strings.Replace(email, "\n", "", 1)

	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.Replace(password, "\n", "", 1)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logrus.Fatalf("Error hashing password: %s", err.Error())
	}

	if _, err := store.pool.Exec("INSERT INTO users (login_name, name, email, password) VALUES ($1, $2, $3, $4)", loginName, name, email, hash); err != nil {
		logrus.Fatalf("Error inserting user: %s", err.Error())
	}
}

func generateKey() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		logrus.Fatalf("Error generating random key: %s", err.Error())
	}

	fmt.Printf("Base 64 key: %s\n", base64.StdEncoding.EncodeToString(key))
}

func main() {
	logrus.SetOutput(os.Stdout)

	logLevel := strings.ToLower(Getenv("LOG_LEVEL", "info"))
	level := logrus.InfoLevel
	switch logLevel {
	case "debug":
		level = logrus.DebugLevel
	case "info":
		level = logrus.InfoLevel
	case "warn":
		level = logrus.WarnLevel
	case "error":
		level = logrus.ErrorLevel
	case "fatal":
		level = logrus.FatalLevel
	case "panic":
		level = logrus.PanicLevel
	}
	logrus.SetLevel(level)

	if len(os.Args) == 2 && os.Args[1] == "generate-key" {
		generateKey()
		return
	}

	envPort := Getenv("SSSO_DB_PORT", "5432")
	port, err := strconv.Atoi(envPort)
	if err != nil {
		logrus.Fatalf("Unable to parse db port: %s", envPort)
	}

	config := StoreConfiguration{
		Host:      Getenv("SSSO_DB_HOST", "localhost"),
		Port:      uint16(port),
		Database:  Getenv("SSSO_DB_NAME", "postgres"),
		Username:  Getenv("SSSO_DB_USERNAME", "postgres"),
		Password:  Getenv("SSSO_DB_PASSWORD", ""),
		Base64Key: Getenv("SSSO_KEY", "5247DBA0A29CBBBF9DED3C907B7E0DE9"),
	}

	logrus.Debug("Configuration %v", config)

	store, err := NewStore(context.Background(), config)
	if err != nil {
		logrus.Errorf("Error initializing store: %s. Retrying...", err)
		time.Sleep(3 * time.Second)
		store, err = NewStore(context.Background(), config)
		if err != nil {
			logrus.Fatalf("Error initializing store: %s.", err)
		}
	}
	defer store.Close()

	if len(os.Args) == 2 && os.Args[1] == "insert-user" {
		insertUser(store)
		return
	}

	http.Handle("/authenticate", &AuthHandler{store})
	http.Handle("/login", NewLoginHandler(store, Getenv("SSSO_DOMAIN", "mydomain.com"), Getenv("SSSO_DATA", "")+"login.html"))
	http.Handle("/logout", &LogoutHandler{cookieDomain: Getenv("SSSO_DOMAIN", "mydomain.com")})
	http.Handle("/me", NewMeHandler(store, Getenv("SSSO_DATA", "")+"me.html"))
	http.Handle("/api", &APIHandler{store})
	addr := Getenv("SSSO_ADDRESS", ":80")

	server := &http.Server{Addr: addr}
	done := make(chan struct{})

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop)
		<-stop

		logrus.Info("Shutting down the server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			logrus.Errorf("Error shutting down the server: %s", err.Error())
		} else {
			logrus.Info("Server stopped")
		}
		cancel()
		close(done)
	}()

	logrus.Infof("Starting server on %s", addr)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logrus.Fatal(err)
	}

	<-done

}
