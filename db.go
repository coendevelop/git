package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
)

type AuthStore struct {
	db *sql.DB
}

func NewAuthStore(dbPath string) (*AuthStore, error) {
	// 1. Ensure the directory for the DB exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// 2. Open the database (creates the file if it doesn't exist)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, token TEXT UNIQUE, user_id INTEGER, expires_at DATETIME);
    `)
	return &AuthStore{db: db}, err
}

func (s *AuthStore) GetUserByKey(incomingKey ssh.PublicKey) (string, error) {
	// 1. Convert the incoming key to the standard "authorized_keys" format
	// This looks like "ssh-rsa AAAAB3Nza..."
	incomingBytes := ssh.MarshalAuthorizedKey(incomingKey)
	incomingString := string(incomingBytes)

	// 2. Query the DB for the username associated with this exact key string
	// This is much faster than a loop because SQLite uses indexing
	var username string
	query := `
        SELECT users.username 
        FROM users 
        JOIN public_keys ON users.id = public_keys.user_id 
        WHERE public_keys.key_data = ?`

	err := s.db.QueryRow(query, incomingString).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("public key not recognized")
		}
		return "", err
	}

	return username, nil
}

func (s *AuthStore) HandleCheckUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&exists)
	if err != nil {
		http.Error(w, "DB Error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if exists {
		fmt.Fprint(w, `{"exists": true}`)
	} else {
		fmt.Fprint(w, `{"exists": false}`)
	}
}
