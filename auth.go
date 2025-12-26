package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *AuthStore) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
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

// Use the pointer to AuthStore, but w is passed by interface
func (s *AuthStore) setSessionCookie(w http.ResponseWriter, username string) {
	token, err := s.CreateSession(username)
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		return
	}

	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	// Add this log to confirm the token being sent
	log.Printf("DEBUG: Setting cookie for %s: %s", username, token)
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
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		pw := r.FormValue("password")
		confirm := r.FormValue("confirm_password")

		if pw != confirm {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		err := s.RegisterUser(username, pw)
		if err != nil {
			log.Printf("REGISTRATION FAIL: %v", err)
			http.Error(w, "Could not create user", 500)
			return
		}

		// 2. Create session and SET THE COOKIE
		// Make sure s.setSessionCookie actually calls http.SetCookie(w, ...)
		s.setSessionCookie(w, username)

		// 3. LOG to verify the cookie was at least attempted
		log.Printf("Registration successful for %s, redirecting to dashboard", username)

		// 4. Redirect
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// ... render template for GET
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
		http.Redirect(w, r, "/auth", http.StatusUnauthorized)
		time.Sleep(5)
		return
	}

	s.setSessionCookie(w, username)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
func (s *AuthStore) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// 1. Get the token from the cookie
	cookie, err := r.Cookie("session_token")
	if err == nil {
		// 2. Delete from database if it exists
		s.DeleteSession(cookie.Value)
	}

	// 3. Tell the browser to delete the cookie
	newCookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,              // Forces immediate expiration
		Expires:  time.Unix(0, 0), // Old-school compatibility
	}
	http.SetCookie(w, newCookie)

	log.Printf("Successful logout for %s", cookie.Value)
	// 4. Redirect to the all-in-one auth page
	http.Redirect(w, r, "/auth", http.StatusSeeOther)
}
