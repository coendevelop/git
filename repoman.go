package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoManager handles the physical git files
type RepoManager struct {
	BaseDir string
	Store   *AuthStore
}

// getAuthenticatedUser is a helper to DRY up our auth logic
func (m *RepoManager) getAuthenticatedUser(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return m.Store.GetUserByToken(cookie.Value)
}

// TODO: Add repo to database
func (m *RepoManager) CreateRepo(username, repoName string) error {
	// Sanitize inputs to prevent directory traversal attacks
	username = filepath.Clean(username)
	repoName = filepath.Clean(repoName)

	// Build path: storage/username/reponame.git
	repoPath := filepath.Join(m.BaseDir, username, repoName+".git")

	// 1. Create the user's directory if it doesn't exist
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 2. Initialize bare repository
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = repoPath

	return cmd.Run()
}

// TODO: Add check for loggeduser = reponame
// TODO: remove repo from database
func (m *RepoManager) DeleteRepo(username, repoName string) error {
	// Sanitize inputs to prevent directory traversal attacks
	username = filepath.Clean(username)
	repoName = filepath.Clean(repoName)

	// Build removal path
	repoPath := filepath.Join(m.BaseDir + username + repoName)

	// Remove directory
	if err := os.RemoveAll(repoPath); err != nil {
		return fmt.Errorf("failed to remove directory %w", err)
	}

	return nil
}

// TODO: Return ALL repos from database
// TODO: Add checks for "Private Repository" or "Private Profile"
// Return a list of repositories
func (m *RepoManager) ListRepos(username string) ([]string, error) {
	// 1. Sanitize and build the path
	userPath := filepath.Join(m.BaseDir, filepath.Clean(username))

	// 2. Read the directory entries
	entries, err := os.ReadDir(userPath)
	if err != nil {
		// If the user directory doesn't exist, return an error
		os.Mkdir(m.BaseDir+"/"+filepath.Clean(username), 0755)
	}

	var repos []string
	for _, entry := range entries {
		// 3. Only add it to the list if it's a directory
		if entry.IsDir() {
			// Clean up the name by removing the ".git" suffix for a cleaner list
			name := strings.TrimSuffix(entry.Name(), ".git")
			repos = append(repos, name)
		}
	}

	return repos, nil
}

// Return contents of a repository
/*func (m *RepoManager) ListContents(username, reponame string) ([]string, error) {

}
*/
