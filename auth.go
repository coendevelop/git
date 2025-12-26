package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
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

func (s *AuthStore) CreateSession(username string) (string, error) {
	var userID int
	// Case-insensitive lookup thanks to the NOCASE schema
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.Printf("Session Error: User %s not found: %v", username, err)
		return "", err
	}

	token := generateSessionToken() // Your token generator
	expiresAt := time.Now().Add(24 * time.Hour)

	// Ensure the column names (token, user_id, expires_at) match your initSchema exactly
	_, err = s.db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, userID, expiresAt)

	if err != nil {
		log.Printf("Session Error: Failed to insert token into DB: %v", err)
		return "", err
	}

	return token, nil
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

func (s *AuthStore) GetUserByTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return s.GetUserByToken(cookie.Value)
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

func (s *AuthStore) setSessionCookieWithToken(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",   // Essential for the dashboard to see it
		HttpOnly: true,  // Prevents JavaScript access (Security)
		MaxAge:   86400, // 24 hours
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	log.Printf("DEBUG: Cookie 'session_token' set in headers")
}

// Global regex for username validation
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func IsValidUsername(username string) bool {
	// Check length (good practice) and characters
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	return usernameRegex.MatchString(username)
}

func (s *AuthStore) RegisterUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return err
	}

	_, err = s.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hashedPassword))

	if err != nil {
		// Check if this is a "User Already Exists" error
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("user_exists")
		}
		return err
	}
	return nil
}

func (s *AuthStore) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		err := s.RegisterUser(username, password)
		if err != nil {
			// If the user already exists, we don't want to show a scary error
			if strings.Contains(err.Error(), "user_exists") {
				log.Printf("User %s already exists, attempting auto-login", username)
				// Proceed to session creation if you want auto-login,
				// but usually, you'd verify the password first!
			} else {
				http.Error(w, "Registration failed", 500)
				return
			}
		}

		// Now create the session - this is where the 'No Rows' fix happens
		token, err := s.CreateSession(username)
		if err != nil {
			log.Printf("Failed to create session after registration: %v", err)
			http.Error(w, "Session creation failed", 500)
			return
		}

		s.setSessionCookieWithToken(w, token)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func (s *AuthStore) Authenticate(username, password string) (bool, error) {
	var hashedPassword string
	// Case-insensitive lookup
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // User doesn't exist
		}
		return false, err
	}

	// Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil // Password mismatch
	}

	return true, nil
}

func (s *AuthStore) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		ok, err := s.Authenticate(username, password)
		if err != nil || !ok {
			log.Printf("Login failed for user: %s", username)
			http.Error(w, "Invalid username or password", http.StatusUnauthorized) // 401
			return
		}

		// Success! Create session and set cookie
		token, _ := s.CreateSession(username)
		s.setSessionCookieWithToken(w, token)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
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
func (m *RepoManager) GetUsernameFromSession(r *http.Request) string {
	// 1. Extract the token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "" // Not logged in
	}

	// 2. Query the DB to find the username associated with this token
	var username string
	query := `
        SELECT u.username 
        FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP`

	err = m.Store.db.QueryRow(query, cookie.Value).Scan(&username)
	if err != nil {
		log.Printf("Session lookup failed: %v", err)
		return ""
	}

	return username
}
