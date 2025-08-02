package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

var (
	jwtSecret []byte
	config    Config
)

func loadJwt() error {
	const secretFile = "secret.jwt"
	const secretSize = 256

	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		secret := make([]byte, secretSize)
		_, err := rand.Read(secret)
		if err != nil {
			return fmt.Errorf("failed to generate secret: %v", err)
		}

		encoded := base64.StdEncoding.EncodeToString(secret)
		if err := os.WriteFile(secretFile, []byte(encoded), 0600); err != nil {
			return fmt.Errorf("failed to write secret file: %v", err)
		}
		jwtSecret = secret
	} else {
		data, err := os.ReadFile(secretFile)
		if err != nil {
			return fmt.Errorf("failed to read secret file: %v", err)
		}
		secret, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return fmt.Errorf("failed to decode secret: %v", err)
		}
		jwtSecret = secret
	}

	return nil
}

func main() {
	ShowTheBanner()

	LogTask("Configure bind", func() error {
		bind, bindSet := os.LookupEnv("SC_BIND")
		port, portSet := os.LookupEnv("SC_PORT")

		if !bindSet {
			bind = "0.0.0.0"
		} else {
			if bind == "" {
				return fmt.Errorf("bind cannot be empty")
			}
		}

		if !portSet {
			port = "8080"
		} else {
			if port == "" {
				return fmt.Errorf("port cannot be empty")
			}
		}

		config = Config{
			Bind: bind,
			Port: port,
		}

		return nil
	})

	LogTask("Load JWT", func() error {
		return loadJwt()
	})

	LogTask("Initialise database", func() error {
		return initDB()
	})
	defer db.Close()

	err := runMigrations()
	if err != nil {
		LogFatal(fmt.Sprintf("failed to apply migrations: %v", err))
	}

	r := mux.NewRouter()
	r.HandleFunc("/gateway", gatewayHandler)
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/message", messageHandler).Methods("POST")
	r.HandleFunc("/api/logout", logoutHandler).Methods("POST")

	LogSuccess(fmt.Sprintf("Binding server to http://%s", config.GetBindAddress()))

	err = http.ListenAndServe(config.GetBindAddress(), LoggingMiddleware(r))
	if err != nil {
		LogFatal(err.Error())
	}
}
