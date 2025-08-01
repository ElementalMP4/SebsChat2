package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// Global map and mutex for thread safety
var (
	userSessions = make(map[string]*websocket.Conn)
	sessionsMu   sync.Mutex
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	// Get token from Sec-WebSocket-Protocol header
	authHeader := r.Header.Get("Sec-WebSocket-Protocol")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	// Parse and validate JWT, extract username from claims
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
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Username not found in token", http.StatusUnauthorized)
		return
	}

	// Echo back the Sec-WebSocket-Protocol header
	upgrader.Subprotocols = []string{authHeader}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}

	defer func() {
		// Remove user from map on disconnect
		conn.Close()
		sessionsMu.Lock()
		delete(userSessions, username)
		sessionsMu.Unlock()
		log.Printf("User %s has disconnected\n", username)
	}()

	// Add user to map
	sessionsMu.Lock()
	userSessions[username] = conn
	sessionsMu.Unlock()

	log.Printf("User %s has connected\n", username)

	// Send OK message
	msg := WebSocketMessage{
		Type: WS_CONNECT_OK,
		Payload: JustOneMessage{
			Message: "Connected",
		},
	}

	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("Failed to marshal message:", err)
		return
	}
	conn.WriteMessage(websocket.TextMessage, jsonMsg)

	// Keep the connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			// Client disconnected or error occurred
			break
		}
		// Optionally, handle incoming messages here
	}
}
