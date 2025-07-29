package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var db *sql.DB

var jwtSecret []byte

func init() {
	const secretFile = "secret.jwt"
	const secretSize = 256

	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		// Generate a new 256-byte secret
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

type User struct {
	ID             int
	Username       string
	HashedPassword string
	TOTPSecret     string
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	Username   string `json:"username"`
	TOTPSecret string `json:"totp_secret"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err)
	}
	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        hashed_password TEXT NOT NULL,
        totp_secret TEXT NOT NULL
    );`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

// Create a new user
func CreateUser(username, hashedPassword, totpSecret string) (*User, error) {
	res, err := db.Exec("INSERT INTO users (username, hashed_password, totp_secret) VALUES (?, ?, ?)", username, hashedPassword, totpSecret)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: int(id), Username: username, HashedPassword: hashedPassword, TOTPSecret: totpSecret}, nil
}

// Update an existing user
func UpdateUser(id int, username, hashedPassword, totpSecret string) error {
	_, err := db.Exec("UPDATE users SET username=?, hashed_password=?, totp_secret=? WHERE id=?", username, hashedPassword, totpSecret, id)
	return err
}

// Delete a user
func DeleteUser(id int) error {
	_, err := db.Exec("DELETE FROM users WHERE id=?", id)
	return err
}

// Get a user by username
func GetUserByUsername(username string) (*User, error) {
	row := db.QueryRow("SELECT id, username, hashed_password, totp_secret FROM users WHERE username=?", username)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.HashedPassword, &user.TOTPSecret)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("API endpoint"))
}

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	// Get token from Sec-WebSocket-Protocol header
	authHeader := r.Header.Get("Sec-WebSocket-Protocol")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		fmt.Println("Auth header bad")
		return
	}
	tokenString := authHeader[7:]

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Println("Signing method bad")
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		fmt.Printf("Token bad %v\n", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Echo back the Sec-WebSocket-Protocol header
	upgrader.Subprotocols = []string{authHeader}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Send OK message
	conn.WriteMessage(websocket.TextMessage, []byte("OK"))

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		fmt.Printf("Received: %s\n", msg)
		conn.WriteMessage(websocket.TextMessage, []byte("Echo: "+string(msg)))
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Check if username exists
	_, err := GetUserByUsername(req.Username)
	if err == nil {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}
	// If error is not sql.ErrNoRows, something else went wrong
	if err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Generate TOTP secret
	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SebsChat",
		AccountName: req.Username,
		Period:      30,
		SecretSize:  20,
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}

	// Create user
	_, err = CreateUser(req.Username, string(hashedPassword), totpSecret.Secret())
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	resp := RegisterResponse{
		Username:   req.Username,
		TOTPSecret: totpSecret.Secret(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	user, err := GetUserByUsername(req.Username)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	// Check TOTP code
	if !totp.Validate(req.TOTPCode, user.TOTPSecret) {
		http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
		return
	}
	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	resp := LoginResponse{Token: tokenString}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/api", apiHandler).Methods("GET")
	r.HandleFunc("/gateway", gatewayHandler)
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")

	fmt.Println("Server started on :8080")
	http.ListenAndServe(":8080", r)
}
