package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

var jwtSecret []byte

func init() {
	const secretFile = "secret.jwt"
	const secretSize = 256

	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		secret := make([]byte, secretSize)
		_, err := rand.Read(secret)
		if err != nil {
			log.Fatalf("Failed to generate secret: %v", err)
		}

		encoded := base64.StdEncoding.EncodeToString(secret)
		if err := os.WriteFile(secretFile, []byte(encoded), 0600); err != nil {
			log.Fatalf("Failed to write secret file: %v", err)
		}
		jwtSecret = secret
	} else {
		data, err := os.ReadFile(secretFile)
		if err != nil {
			log.Fatalf("Failed to read secret file: %v", err)
		}
		secret, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			log.Fatalf("Failed to decode secret: %v", err)
		}
		jwtSecret = secret
	}
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/gateway", gatewayHandler)
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/message", messageHandler).Methods("POST")
	r.HandleFunc("/api/logout", logoutHandler).Methods("POST")

	fmt.Println("Server started on :8080")
	http.ListenAndServe(":8080", LoggingMiddleware(r))
}
