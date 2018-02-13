package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
		log.Fatalf("Error hashing password: %s\n", err.Error())
	}

	if _, err := store.pool.Exec("INSERT INTO users (login_name, name, email, password) VALUES ($1, $2, $3, $4)", loginName, name, email, hash); err != nil {
		log.Fatalf("Error inserting user: %s\n", err.Error())
	}
}

func main() {
	log.SetOutput(os.Stdout)

	envPort := Getenv("SSSO_DB_PORT", "5432")
	port, err := strconv.Atoi(envPort)
	if err != nil {
		log.Fatalf("Unable to parse db port: %s", envPort)
	}

	config := StoreConfiguration{
		Host:      Getenv("SSSO_DB_HOST", "localhost"),
		Port:      uint16(port),
		Database:  Getenv("SSSO_DB_NAME", "postgres"),
		Username:  Getenv("SSSO_DB_USERNAME", "postgres"),
		Password:  Getenv("SSSO_DB_PASSWORD", ""),
		Base64Key: Getenv("SSSO_KEY", "5247DBA0A29CBBBF9DED3C907B7E0DE9"),
	}

	store, err := NewStore(context.Background(), config)
	if err != nil {
		log.Fatalf("ERROR initializing store: %s", err)
	}
	defer store.Close()

	if len(os.Args) == 2 && os.Args[1] == "insert-user" {
		insertUser(store)
		return
	}

	http.Handle("/authenticate", &AuthHandler{store})
	http.Handle("/login", &LoginHandler{store: store, cookieDomain: Getenv("SSSO_DOMAIN", "mydomain.com")})
	http.Handle("/logout", &LogoutHandler{})
	http.Handle("/me", &MeHandler{store})
	http.Handle("/api", &APIHandler{store})
	http.ListenAndServe(Getenv("SSSO_ADDRESS", ":80"), nil)
}
