package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

type FileInfo struct {
	Name  string
	IsURL bool
	Size  int64
}

type RepoManager struct {
	BaseDir       string
	Store         *AuthStore
	templateCache map[string]*template.Template
}

// NewRepoManager now initializes the templates once
func NewRepoManager(baseDir string, store *AuthStore) (*RepoManager, error) {
	mgr := &RepoManager{
		BaseDir:       baseDir,
		Store:         store,
		templateCache: make(map[string]*template.Template),
	}

	// Pre-parse all templates in the folder
	tmplFiles, err := filepath.Glob("templates/*.tmpl")
	if err != nil {
		return nil, err
	}

	for _, file := range tmplFiles {
		name := filepath.Base(file)
		t, err := template.ParseFiles(file)
		if err != nil {
			return nil, fmt.Errorf("error parsing template %s: %v", name, err)
		}
		mgr.templateCache[name] = t
	}

	return mgr, nil
}

func (m *RepoManager) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := m.templateCache[name]
	if !ok {
		log.Printf("TEMPLATE ERROR: %s not found in cache", name)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("RENDER ERROR: %s: %v", name, err)
		// Header is likely already sent, so we log the error
	}
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
		// If the user directory doesn't exist, create it
		os.MkdirAll(userPath, 0755)
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

func (m *RepoManager) GetRepoFiles(username, repoName string) ([]FileInfo, error) {
	repoPath := filepath.Join(m.BaseDir, username, repoName+".git")

	// 1. Open the bare repository
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	// 2. Get the HEAD reference (where the current branch is pointing)
	ref, err := r.Head()
	if err != nil {
		return nil, err // Likely an empty repo with no commits yet
	}

	// 3. Get the latest commit
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return nil, err
	}

	// 4. Get the "Tree" (the file structure) from that commit
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for _, entry := range tree.Entries {
		files = append(files, FileInfo{
			Name:  entry.Name,
			IsURL: entry.Mode.IsFile(),
		})
	}

	return files, nil
}

func (m *RepoManager) HandleRepoView(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate the user (ensure they are logged in)
	username, err := m.Store.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	// 2. Extract repo name from URL: /view/{repoName}
	// Assumes user is viewing their own repo for now
	repoName := strings.TrimPrefix(r.URL.Path, "/view/")
	if repoName == "" {
		http.Error(w, "Repository not specified", http.StatusBadRequest)
		return
	}

	// 3. Get files using go-git
	files, err := m.GetRepoFiles(username, repoName)
	if err != nil {
		// If the repo is empty (no commits), show a specific message
		if err.Error() == "reference not found" {
			m.renderTemplate(w, "repo_empty.tmpl", map[string]interface{}{
				"Username": username,
				"RepoName": repoName,
				"SSHPort":  "2222",
			})
			return
		}
		log.Printf("Error reading repo %s: %v", repoName, err)
		http.Error(w, "Error reading repository", 500)
		return
	}

	// 4. Render the file list
	m.renderTemplate(w, "repo_view.tmpl", map[string]interface{}{
		"Username": username,
		"RepoName": repoName,
		"Files":    files,
	})
	http.Redirect(w, r, filepath.Join("/view", username, repoName), http.StatusSeeOther)
}
