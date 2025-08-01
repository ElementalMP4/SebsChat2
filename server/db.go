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

	createTokensTable := `
    CREATE TABLE IF NOT EXISTS jwt_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );`
	_, err = db.Exec(createTokensTable)
	if err != nil {
		log.Fatal(err)
	}

}

func CreateUser(username, hashedPassword, totpSecret string) (*User, error) {
	res, err := db.Exec("INSERT INTO users (username, hashed_password, totp_secret) VALUES (?, ?, ?)", username, hashedPassword, totpSecret)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: int(id), Username: username, HashedPassword: hashedPassword, TOTPSecret: totpSecret}, nil
}

func UpdateUser(id int, username, hashedPassword, totpSecret string) error {
	_, err := db.Exec("UPDATE users SET username=?, hashed_password=?, totp_secret=? WHERE id=?", username, hashedPassword, totpSecret, id)
	return err
}

func DeleteUser(id int) error {
	_, err := db.Exec("DELETE FROM users WHERE id=?", id)
	return err
}

func GetUserByUsername(username string) (*User, error) {
	row := db.QueryRow("SELECT id, username, hashed_password, totp_secret FROM users WHERE username=?", username)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.HashedPassword, &user.TOTPSecret)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func AddTokenJTI(jti, username string, issuedAt, expiresAt int64) error {
	_, err := db.Exec(
		"INSERT INTO jwt_tokens (jti, username, issued_at, expires_at) VALUES (?, ?, ?, ?)",
		jti, username, issuedAt, expiresAt,
	)
	return err
}

func IsJTIValid(jti string) (bool, error) {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM jwt_tokens WHERE jti=? AND expires_at > strftime('%s','now')",
		jti,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func RemoveExpiredJTIs() error {
	_, err := db.Exec("DELETE FROM jwt_tokens WHERE expires_at <= strftime('%s','now')")
	return err
}

func DeleteTokenJTI(jti string) error {
	_, err := db.Exec("DELETE FROM jwt_tokens WHERE jti = ?", jti)
	return err
}
