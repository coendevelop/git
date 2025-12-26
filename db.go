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

const initSchema = `
-- Users Table: Case-insensitive usernames
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Repositories Table: Tracks metadata and download counts
CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_private INTEGER DEFAULT 0, -- 0 for public, 1 for private
    download_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name) -- Prevents a user from having two repos with the same name
);

-- Public Keys Table: For SSH access
CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_data TEXT NOT NULL UNIQUE, 
    label TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions Table: For Web UI access
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_repos_owner_name ON repositories(user_id, name);
`

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

	_, err = db.Exec(initSchema)
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
