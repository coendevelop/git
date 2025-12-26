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
	"github.com/go-git/go-git/v5/plumbing"
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

func NewRepoManager(baseDir string, store *AuthStore) (*RepoManager, error) {
	mgr := &RepoManager{
		BaseDir: baseDir,
		Store:   store,
	}

	// 1. Initialize an empty template set
	tmplSet := template.New("")

	// 2. Walk through the templates directory
	err := filepath.Walk("templates", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 3. Only process .tmpl files
		if !info.IsDir() && strings.HasSuffix(path, ".tmpl") {
			// Create the name: e.g., "auth.tmpl" or "base/footer.tmpl"
			name := strings.TrimPrefix(path, "templates/")
			name = filepath.ToSlash(name) // Ensure forward slashes on Windows

			// Read the file content
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			// 4. Associate the content with the specific name in the set
			_, err = tmplSet.New(name).Parse(string(b))
			if err != nil {
				return err
			}
			log.Printf("Loaded template into set: %s", name)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	mgr.templateCache = map[string]*template.Template{
		"root": tmplSet,
	}

	return mgr, nil
}

func (m *RepoManager) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	// We always use the "root" set
	tmpl := m.templateCache["root"]

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// ExecuteTemplate looks for the specific name WITHIN the set
	err := tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("RENDER ERROR: %s: %v", name, err)
		http.Error(w, "Template error", 500)
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

func (m *RepoManager) HandleCreateRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Get user context
	username, err := m.Store.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	// 2. Get repo name from form
	repoName := r.FormValue("name")
	if repoName == "" {
		http.Error(w, "Repository name is required", http.StatusBadRequest)
		return
	}

	// 3. Construct path: ./data/repos/username/repoName.git
	repoPath := filepath.Join(m.BaseDir, username, repoName+".git")

	// 4. Execute git init --bare
	// Ensure the parent directory exists first
	os.MkdirAll(filepath.Dir(repoPath), 0755)

	cmd := exec.Command("git", "init", "--bare", repoPath)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to init repo %s: %v", repoPath, err)
		http.Error(w, "Failed to create repository", http.StatusInternalServerError)
		return
	}

	targetURL := fmt.Sprintf("/view/%s/%s", username, repoName)
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
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

func (m *RepoManager) ListUserRepos(username string) ([]string, error) {
	userDir := filepath.Join(m.BaseDir, username)

	// DEBUG: Copy this path from your terminal and check it in your file explorer
	log.Printf("DEBUG: Looking for repos in: %s", userDir)

	// Create the directory if it doesn't exist yet
	if _, err := os.Stat(userDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	files, err := os.ReadDir(userDir)
	if err != nil {
		return nil, err
	}

	var repos []string
	for _, f := range files {
		if f.IsDir() && strings.HasSuffix(f.Name(), ".git") {
			// Remove the .git suffix for the UI display
			repos = append(repos, strings.TrimSuffix(f.Name(), ".git"))
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
			m.renderTemplate(w, "repo_view.tmpl", map[string]interface{}{
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

func (m *RepoManager) HandleRepoNavigation(w http.ResponseWriter, r *http.Request, username, repo, branchName, path string) {
	repoPath := filepath.Join(m.BaseDir, username, repo+".git")
	gitRepo, _ := git.PlainOpen(repoPath)

	// 1. Get all branches for the dropdown
	branchIter, _ := gitRepo.Branches()
	var branches []string
	branchIter.ForEach(func(ref *plumbing.Reference) error {
		branches = append(branches, ref.Name().Short())
		return nil
	})

	// 2. Get the hash of the SELECTED branch
	branchRef, _ := gitRepo.Reference(plumbing.NewBranchReferenceName(branchName), true)
	// Fallback if branch doesn't exist
	if branchRef == nil {
		branchRef, _ = gitRepo.Head()
	}

	commit, _ := gitRepo.CommitObject(branchRef.Hash())
	tree, _ := commit.Tree()

	data := map[string]interface{}{
		"Owner":         username,
		"RepoName":      repo,
		"CurrentBranch": branchName,
		"Branches":      branches,
		"CurrentPath":   path,
		"LastCommit": map[string]interface{}{
			"Message": commit.Message,
			"Author":  commit.Author.Name,
			"Date":    commit.Author.When.Format("Jan 02, 2006"),
			"Hash":    commit.Hash.String(),
		},
	}

	// 3. Logic for Files vs Folders
	if path == "" {
		data["Files"] = tree.Entries
		m.renderTemplate(w, "repo_view.tmpl", data)
	} else {
		// CLEAN THE PATH: Git tree search fails with leading slashes
		cleanPath := strings.Trim(path, "/")
		entry, err := tree.FindEntry(cleanPath)

		if err != nil {
			log.Printf("REDIRECT: Git path '%s' not found", cleanPath)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if entry.Mode.IsFile() {
			file, _ := tree.File(cleanPath)
			content, _ := file.Contents()

			data["FileName"] = entry.Name
			data["Content"] = content
			// Ensure this matches your file precisely
			m.renderTemplate(w, "file_view.tmpl", data)
		} else {
			subTree, _ := tree.Tree(cleanPath)
			data["Files"] = subTree.Entries
			m.renderTemplate(w, "repo_view.tmpl", data)
		}
	}
}
func (m *RepoManager) HandleView(w http.ResponseWriter, r *http.Request) {
	pathStr := strings.TrimPrefix(r.URL.Path, "/view/")
	pathStr = strings.Trim(pathStr, "/")
	parts := strings.Split(pathStr, "/")

	if len(parts) < 2 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := parts[0]
	repoName := parts[1]

	// Default branch to main/master if not specified
	branch := "main"
	internalPath := ""

	// If URL is /view/michael/nice/develop/src/main.go
	// parts[2] is the branch "develop"
	if len(parts) > 2 {
		branch = parts[2]
	}
	if len(parts) > 3 {
		internalPath = strings.Join(parts[3:], "/")
	}

	m.HandleRepoNavigation(w, r, username, repoName, branch, internalPath)
}
