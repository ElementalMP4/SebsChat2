package main

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
