package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

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
	now := time.Now().Unix()
	exp := now + int64((time.Hour * 24 * 30).Seconds()) // 30 days

	jti := uuid.NewString()
	claims := jwt.MapClaims{
		"username": user.Username,
		"iat":      now,
		"nbf":      now,
		"exp":      exp,
		"jti":      jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Save the token ID
	if err := AddTokenJTI(jti, user.Username, now, exp); err != nil {
		http.Error(w, "Failed to persist token", http.StatusInternalServerError)
		return
	}
	resp := LoginResponse{Token: tokenString}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func messageHandler(w http.ResponseWriter, r *http.Request) {
	// Check Authorization header for Bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Check JWT claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Check username
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Username not found in token", http.StatusUnauthorized)
		return
	}

	// Check JWT ID
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		http.Error(w, "JTI not found in token", http.StatusUnauthorized)
		return
	}

	valid, err := IsJTIValid(jti)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Token has been revoked or expired", http.StatusUnauthorized)
		return
	}

	var msg EncryptedMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if msg.Sender != username {
		http.Error(w, "Sender does not match token", http.StatusUnauthorized)
		return
	}

	receipt := uuid.NewString()
	var sentTo []string

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	for recipient := range msg.EncryptedKeys {
		conn, ok := userSessions[recipient]
		if !ok {
			continue // user not online
		}

		// Strip out irrelevant keys
		userMsg := msg
		userMsg.EncryptedKeys = map[string]string{
			recipient: msg.EncryptedKeys[recipient],
		}
		userMsg.Receipt = receipt

		wsMsg := WebSocketMessage{
			Type:    WS_CHAT_MESSAGE,
			Payload: userMsg,
		}

		jsonMsg, err := json.Marshal(wsMsg)
		if err != nil {
			fmt.Println("Failed to marshal message for", recipient, ":", err)
			continue
		}

		if err := conn.WriteMessage(websocket.TextMessage, jsonMsg); err != nil {
			fmt.Println("Failed to send message to", recipient, ":", err)
			continue
		}

		sentTo = append(sentTo, recipient)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SendReceipt{
		Receipt: receipt,
		SentTo:  sentTo,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		http.Error(w, "JTI not found in token", http.StatusUnauthorized)
		return
	}

	err = DeleteTokenJTI(jti)
	if err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(JustOneMessage{
		Message: "Logged out",
	})
}
