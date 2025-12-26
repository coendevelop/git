package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
)

const schema = `
-- 1. Users table: Stores identity and web credentials
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Public Keys table: Maps SSH keys to users
-- Note: key_data stores the full "ssh-rsa AAA..." string
CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_data TEXT NOT NULL,
    label TEXT, -- e.g., "Work Laptop"
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Sessions table: Maps random tokens to users for Web UI auth
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Optimization: Index the session tokens for fast lookups
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
-- Optimization: Index key_data for fast SSH authentication
CREATE INDEX IF NOT EXISTS idx_public_keys_data ON public_keys(key_data);`

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

	// 3. Execute the schema
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &AuthStore{db: db}, nil
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
