package main

import (
	"database/sql"
	"log"
)

var db *sql.DB

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
