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

// generateSessionToken returns a URL-safe random token suitable for session IDs.
// It uses 32 bytes of cryptographically secure random data and base64 URL
// encoding to avoid characters that need escaping in cookies.
func generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand rarely fails; ignore error in this context
	return base64.URLEncoding.EncodeToString(b)
}

// DeleteSession removes a session identified by `token` from the store.
func (s *AuthStore) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

// CreateSession creates and persists a session token for `username` and returns
// the token. The session expires in 24 hours. Returns an error if the user is
// not found or inserting the session fails.
func (s *AuthStore) CreateSession(username string) (string, error) {
	var userID int
	// Case-insensitive lookup thanks to the NOCASE schema
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.Printf("Session Error: User %s not found: %v", username, err)
		return "", err
	}

	token := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Persist the token. Expect columns: token, user_id, expires_at.
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

// GetUserByTokenFromRequest extracts the session cookie from the request and
// returns the associated username via GetUserByToken. If the cookie is missing
// or invalid, an error is returned.
func (s *AuthStore) GetUserByTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return s.GetUserByToken(cookie.Value)
}

// setSessionCookie creates a session (DB) and sets a secure cookie on the
// response. Cookies are marked HttpOnly and use SameSite=Lax to reduce CSRF
// risk while keeping reasonable UX for navigation.
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
	// Log the presence of a cookie for debugging; avoid logging tokens in
	// production unless behind redaction/logging controls.
	log.Printf("DEBUG: Setting cookie for %s", username)
}

// setSessionCookieWithToken sets the given `token` on the response cookie.
// This is useful when a token has already been generated and persisted.
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
	log.Printf("DEBUG: session cookie set")
}

// usernameRegex matches allowed characters for usernames: letters, digits,
// dots, underscores and hyphens. Length is enforced separately.
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// IsValidUsername returns true if the username length is acceptable and the
// characters match the allowed set. This is used during registration.
func IsValidUsername(username string) bool {
	// Check length (good practice) and characters
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	return usernameRegex.MatchString(username)
}

// RegisterUser creates a new user with a bcrypt-hashed password. If the
// username is already taken the function returns an error that contains
// "user_exists" so callers can react appropriately (e.g., auto-login).
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

// HandleRegister handles POSTed registration forms. It creates a new user
// and then creates a session. If the username already exists the code logs an
// informational message and proceeds to session creation (auto-login), which
// may be desired behavior in some deployments.
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

// Authenticate checks whether the given username/password pair is valid.
// Returns (true, nil) on success, (false, nil) for invalid credentials, and
// (false, err) if a DB error occurred.
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

// HandleLogin processes POSTed login forms. On successful authentication
// it creates a session and redirects to /dashboard. Invalid credentials return
// a 401 Unauthorized response.
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

// HandleLogout invalidates the session both in the DB (if present) and in
// the client by setting an expired cookie. The handler then redirects the
// user to the auth page.
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

	if cookie != nil {
		log.Printf("Successful logout for %s", cookie.Value)
	}
	// 4. Redirect to the all-in-one auth page
	http.Redirect(w, r, "/auth", http.StatusSeeOther)
}

// GetUsernameFromSession returns the username associated with the session
// token present in the request cookie. If the user is not logged in or an
// error occurs, an empty string is returned.
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
