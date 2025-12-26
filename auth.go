package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
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

func (s *AuthStore) setSessionCookie(w http.ResponseWriter, username string) {
	token, err := s.CreateSession(username)
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		return
	}

	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",                  // MUST be "/" so the Dashboard can see it
		HttpOnly: true,                 // Security best practice
		Secure:   false,                // Set to true only if using HTTPS
		MaxAge:   86400,                // 24 hours in seconds
		SameSite: http.SameSiteLaxMode, // Helps with modern browser redirects
	}

	http.SetCookie(w, cookie)
	log.Printf("Cookie set successfully for user: %s", username)
}

func (s *AuthStore) RegisterUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return fmt.Errorf("hashing failed: %w", err)
	}

	_, err = s.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hashedPassword))

	if err != nil {
		// This will print the EXACT reason (e.g., "UNIQUE constraint failed" or "no such table")
		log.Printf("SQL Error during registration: %v", err)
		return fmt.Errorf("db insert failed: %w", err)
	}
	return nil
}

func (s *AuthStore) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFS(templateFiles, "templates/register.html")
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// 1. Attempt registration
		err := s.RegisterUser(username, password)
		if err != nil {
			// If it fails (e.g., user already exists), tell the user and STOP
			log.Printf("Registration error: %v", err)
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		// 2. Set the session cookie
		s.setSessionCookie(w, username)

		// 3. IMPORTANT: Redirect immediately to prevent a "Refresh" or "Double Click" from re-submitting
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return // Ensure we stop execution here
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

	s.setSessionCookie(w, username)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
