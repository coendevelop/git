package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// CreateSession generates a token and saves it to the DB
func (s *AuthStore) CreateSession(username string) (string, error) {
	token := generateSessionToken()

	// Get user ID from username
	var userID int
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return "", err
	}

	// Save session (valid for 24 hours)
	_, err = s.db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 day'))",
		token, userID)

	return token, err
}

// GetUserByToken validates a token and returns the username
func (s *AuthStore) GetUserByToken(token string) (string, error) {
	var username string
	query := `
		SELECT users.username FROM users 
		JOIN sessions ON users.id = sessions.user_id 
		WHERE sessions.token = ? AND sessions.expires_at > datetime('now')`

	err := s.db.QueryRow(query, token).Scan(&username)
	if err != nil {
		return "", err
	}
	return username, nil
}

func setSessionCookie(w http.ResponseWriter, username string) {
	cookie := &http.Cookie{
		Name:     "session_user",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		MaxAge:   86400, // Keeps the user logged in for 24 hours
	}
	http.SetCookie(w, cookie)
}

func (s *AuthStore) RegisterUser(username, password string) error {
	// 1. Hash the password
	// Cost 10 is a good balance between security and speed
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return err
	}

	// 2. Insert into database
	_, err = s.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hashedPassword))
	return err
}

func (s *AuthStore) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve your register.html file
		tmpl, _ := template.ParseFS(templateFiles, "templates/register.tmpl")
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// 1. Save user to DB
		err := s.RegisterUser(username, password)
		if err != nil {
			http.Error(w, "Registration failed", http.StatusConflict)
			return
		}

		// 2. NEW: Automatically set the cookie to log them in
		setSessionCookie(w, username)

		// 3. Redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
}

func (s *AuthStore) VerifyUser(username, password string) (bool, error) {
	var hash string
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // User not found
		}
		return false, err
	}

	// Compare the hash with the plain-text password
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil // Password mismatch
	}

	return true, nil
}

func (s *AuthStore) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFS(templateFiles, "templates/login.tmpl")
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	valid, _ := s.VerifyUser(username, password)
	if !valid {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	setSessionCookie(w, username)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
