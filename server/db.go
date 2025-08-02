package main

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var db *sql.DB

func getSortedMigrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)
	return files, nil
}

func applyMigration(filename string) error {
	content, err := migrationFS.ReadFile("migrations/" + filename)
	if err != nil {
		return err
	}

	_, err = db.Exec(string(content))
	return err
}

func runMigrations() error {
	files, err := getSortedMigrationFiles()
	if err != nil {
		return fmt.Errorf("reading migrations: %w", err)
	}

	for _, file := range files {
		f := file
		LogTask("Apply migration "+f, func() error {
			return applyMigration(f)
		})
	}
	return nil
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		return err
	}
	return nil
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
