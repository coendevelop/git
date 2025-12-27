package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// FileInfo represents a file entry shown in the UI. `IsURL` is true for regular
// files (so renderers can treat them as downloadable), `Size` is optional.
type FileInfo struct {
	Name  string
	IsURL bool
	Size  int64
}

// RepoManager handles repositories on disk, database interactions and
// template rendering for the web UI.
type RepoManager struct {
	BaseDir       string
	Store         *AuthStore
	templateCache map[string]*template.Template
}

// NewRepoManager creates a RepoManager rooted at baseDir and loads all
// templates from the `templates` directory into a template set used for
// rendering. It returns an error if template loading or initialization fails.
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

// renderTemplate executes a named template from the loaded template set
// and writes the result to the provided ResponseWriter. Errors are logged and
// translated into a 500 Template error for the client.
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

// getAuthenticatedUser is a helper to extract the username for the session
// token present in the request. It returns an error when the session is
// missing/invalid.
func (m *RepoManager) getAuthenticatedUser(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return m.Store.GetUserByToken(cookie.Value)
}

// CreateNewRepository initializes a bare git repository on disk for `username`
// and inserts a metadata row in the database. `isPrivate` toggles the
// repositories.is_private flag. On DB failure the repository directory is
// currently left in-place
// TODO: clean up.
func (m *RepoManager) CreateNewRepository(username string, repoName string, isPrivate bool) error {
	// 1. Create the repository on disk (Bare Repo)
	repoPath := filepath.Join(m.BaseDir, username, repoName+".git")
	_, err := git.PlainInit(repoPath, true)
	if err != nil {
		return fmt.Errorf("failed to init git repo: %v", err)
	}

	// 2. Insert metadata into SQLite
	priv := 0
	if isPrivate {
		priv = 1
	}
	query := `
        INSERT INTO repositories (user_id, name, description, is_private)
        VALUES ((SELECT id FROM users WHERE username = ? COLLATE NOCASE), ?, ?, ?)`

	_, err = m.Store.db.Exec(query, username, repoName, "No description provided.", priv)
	if err != nil {
		// If DB fails, you might want to cleanup the folder,
		// but often we just log the error.
		return fmt.Errorf("failed to save repo metadata: %v", err)
	}

	return nil
}

func (m *RepoManager) HandleCreateRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Get username from session (logic varies based on your auth)
	username := m.GetUsernameFromSession(r)
	repoName := r.FormValue("name")
	isPrivate := r.FormValue("is_private") == "1"

	err := m.CreateNewRepository(username, repoName, isPrivate)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	http.Redirect(w, r, "/view/"+username+"/"+repoName+"/main/", http.StatusSeeOther)
}

// DeleteRepo removes a repository directory from disk.
// TODO: we should validate the caller and remove related DB entries as well.
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

// GetRepoFiles returns a list of files from the repository's latest commit
// (HEAD). If the repo is empty or missing, this returns an error.
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

// HandleRepoView renders an overview of a repository's files.
// It reads files using go-git. If the repo is empty
// a friendly message is shown to the user.
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

	// Enforce privacy: if the repo is private and the viewer is not the owner, hide it.
	viewer, _ := m.Store.GetUserByTokenFromRequest(r)
	if isPriv, err := m.IsRepoPrivate(username, repo); err == nil && isPriv && viewer != username {
		http.Error(w, "Repository not found", 404)
		return
	}

	repoPath := filepath.Join(m.BaseDir, username, repo+".git")
	gitRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		log.Printf("ERROR: Could not open repo at %s: %v", repoPath, err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 1. Get all branches for the dropdown
	branchIter, _ := gitRepo.Branches()
	var branches []string
	branchIter.ForEach(func(ref *plumbing.Reference) error {
		branches = append(branches, ref.Name().Short())
		return nil
	})

	// 2. Get the hash of the SELECTED branch
	branchRef, _ := gitRepo.Reference(plumbing.NewBranchReferenceName(branchName), true)

	// FALLBACK: If selected branch doesn't exist, try HEAD
	if branchRef == nil {
		branchRef, _ = gitRepo.Head()
	}

	// --- SAFETY GATE FOR EMPTY REPOS ---
	if branchRef == nil {
		log.Printf("DEBUG: Repo %s is empty. Rendering setup guide.", repo)
		m.renderTemplate(w, "repo_view.tmpl", map[string]interface{}{
			"Owner":         username,
			"RepoName":      repo,
			"CurrentBranch": branchName,
			"IsEmpty":       true,
			"SSHAddr":       r.Host, // Dynamically get your server address
		})
		return
	}
	// -----------------------------------

	// If we reach here, we have a valid branchRef
	commit, _ := gitRepo.CommitObject(branchRef.Hash())
	tree, _ := commit.Tree()

	// Prepare base data
	isFav := false
	// viewer was already retrieved earlier; reuse it
	if viewer != "" {
		if fav, err := m.IsFavorite(viewer, username, repo); err == nil && fav {
			isFav = true
		}
	}
	data := map[string]interface{}{
		"Owner":         username,
		"RepoName":      repo,
		"CurrentBranch": branchName,
		"Branches":      branches,
		"DownloadCount": m.GetDownloadCount(username, repo), // Retrieve count here
		"StarCount":     m.GetStarCount(username, repo),
		"IsFavorite":    isFav,
		"CurrentPath":   path,
		"SSHAddr":       r.Host,
		"LastCommit": map[string]interface{}{
			"Message": commit.Message,
			"Author":  commit.Author.Name,
			"Date":    commit.Author.When.Format("Jan 02, 2006"),
			"Hash":    commit.Hash.String(),
		},
	}

	// Breadcrumbs logic
	var breadcrumbs []map[string]string
	if path != "" {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		accumulatedPath := ""
		for _, part := range parts {
			if accumulatedPath == "" {
				accumulatedPath = part
			} else {
				accumulatedPath = accumulatedPath + "/" + part
			}
			breadcrumbs = append(breadcrumbs, map[string]string{
				"Name": part,
				"Path": accumulatedPath,
			})
		}
	}
	data["Breadcrumbs"] = breadcrumbs

	// 3. Logic for Files vs Folders
	if path == "" {
		data["Files"] = tree.Entries
		m.renderTemplate(w, "repo_view.tmpl", data)
	} else {
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

			ext := filepath.Ext(entry.Name)
			if len(ext) > 0 {
				data["Extension"] = ext[1:]
			} else {
				data["Extension"] = "clike"
			}
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

func (m *RepoManager) HandleDownloadZip(w http.ResponseWriter, r *http.Request) {
	// 1. Get the path after /download/
	pathStr := strings.TrimPrefix(r.URL.Path, "/download/view/")
	pathStr = strings.Trim(pathStr, "/")
	parts := strings.Split(pathStr, "/")

	// Adjusted check: If URL is /download/username/repo/branch, we need 3 parts.
	if len(parts) < 3 {
		log.Printf("DOWNLOAD ERROR: Path too short: %v", parts)
		http.Error(w, "Invalid download path", 400)
		return
	}

	username := parts[0]
	repo := parts[1]
	branchName := parts[2]

	// Enforce privacy: only owner (or authorized users) may download private repos
	viewer, _ := m.Store.GetUserByTokenFromRequest(r)
	if isPriv, err := m.IsRepoPrivate(username, repo); err == nil && isPriv && viewer != username {
		http.Error(w, "Forbidden", 403)
		return
	}

	// FIX: Multi-tiered lookup to find the repo on disk
	possiblePaths := []string{
		filepath.Join(m.BaseDir, username, repo+".git"), // Bare repo
		filepath.Join(m.BaseDir, username, repo),        // Non-bare repo
	}

	var gitRepo *git.Repository
	var openErr error
	for _, p := range possiblePaths {
		gitRepo, openErr = git.PlainOpen(p)
		if openErr == nil {
			break
		}
	}

	if openErr != nil {
		log.Printf("ERROR: Repo not found at any of: %v", possiblePaths)
		http.Error(w, "Repository not found on server", 404)
		return
	}

	// 2. Resolve the branch reference
	branchRef, err := gitRepo.Reference(plumbing.NewBranchReferenceName(branchName), true)
	if err != nil {
		branchRef, _ = gitRepo.Head()
	}

	if branchRef == nil {
		http.Error(w, "Branch not found", 404)
		return
	}

	// Increment the download counter for analytics (best-effort)
	if err := m.IncrementDownloadCount(username, repo); err != nil {
		log.Printf("ERROR: incrementing download count for %s/%s: %v", username, repo, err)
	}

	// 3. Prepare Zip Headers
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s.zip", repo, branchName))

	zw := zip.NewWriter(w)
	defer func() {
		if err := zw.Close(); err != nil {
			log.Printf("Error closing zip writer: %v", err)
		}
	}()

	// 4. Get the tree and stream files
	commit, _ := gitRepo.CommitObject(branchRef.Hash())
	tree, _ := commit.Tree()

	err = tree.Files().ForEach(func(f *object.File) error {
		writer, err := zw.Create(f.Name)
		if err != nil {
			return err
		}

		reader, err := f.Reader()
		if err != nil {
			return err
		}
		defer reader.Close()

		_, err = io.Copy(writer, reader)
		return err
	})

	if err != nil {
		log.Printf("Error during zip generation: %v", err)
	}
}
func (m *RepoManager) IncrementDownloadCount(username, repoName string) error {
	// We join with the users table to find the correct repo based on username
	query := `
        UPDATE repositories 
        SET download_count = download_count + 1 
        WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`

	result, err := m.Store.db.Exec(query, repoName, username)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no repository found for %s/%s", username, repoName)
	}
	return nil
}
func (m *RepoManager) GetDownloadCount(username, repoName string) int {
	var count int
	query := `
        SELECT download_count 
        FROM repositories 
        WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`

	err := m.Store.db.QueryRow(query, repoName, username).Scan(&count)
	if err != nil {
		return 0 // Return 0 if not found or error occurs
	}
	return count
}

// IsRepoPrivate checks whether the repository is marked private. Returns (true, nil) if private.
func (m *RepoManager) IsRepoPrivate(username, repoName string) (bool, error) {
	var isPrivate int
	query := `
        SELECT is_private
        FROM repositories
        WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`

	err := m.Store.db.QueryRow(query, repoName, username).Scan(&isPrivate)
	if err != nil {
		return false, err
	}
	return isPrivate == 1, nil
}

// GetRepoMeta returns download_count, created_at, is_private and star_count for a repo
func (m *RepoManager) GetRepoMeta(username, repoName string) (int, string, bool, int, error) {
	var downloadCount int
	var createdAt string
	var isPrivate int
	var starCount int
	query := `
        SELECT download_count, created_at, is_private, COALESCE(star_count, 0)
        FROM repositories
        WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`

	err := m.Store.db.QueryRow(query, repoName, username).Scan(&downloadCount, &createdAt, &isPrivate, &starCount)
	if err != nil {
		return 0, "", false, 0, err
	}
	return downloadCount, createdAt, isPrivate == 1, starCount, nil
}

// GetStarCount returns current star count for a repo (0 if missing)
func (m *RepoManager) GetStarCount(username, repoName string) int {
	var count int
	query := `SELECT COALESCE(star_count,0) FROM repositories WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`
	if err := m.Store.db.QueryRow(query, repoName, username).Scan(&count); err != nil {
		return 0
	}
	return count
}

// RepoHasCommits returns true if the repo has a HEAD/branches (i.e., some content)
func (m *RepoManager) RepoHasCommits(username, repoName string) bool {
	possiblePaths := []string{
		filepath.Join(m.BaseDir, username, repoName+".git"),
		filepath.Join(m.BaseDir, username, repoName),
	}
	for _, p := range possiblePaths {
		gitRepo, err := git.PlainOpen(p)
		if err != nil {
			continue
		}
		// If HEAD exists, repo has commits
		if _, err := gitRepo.Head(); err == nil {
			return true
		}
		// Otherwise, check branches
		br, err := gitRepo.Branches()
		if err == nil {
			has := false
			br.ForEach(func(ref *plumbing.Reference) error {
				has = true
				return nil
			})
			if has {
				return true
			}
		}
	}
	return false
}

// Favorites management
func (m *RepoManager) AddFavorite(user, owner, repoName string) error {
	query := `
	INSERT OR IGNORE INTO favorites (user_id, repo_id) VALUES (
	    (SELECT id FROM users WHERE username = ? COLLATE NOCASE),
	    (SELECT id FROM repositories WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE))
	)`
	res, err := m.Store.db.Exec(query, user, repoName, owner)
	if err != nil {
		return err
	}
	if ra, _ := res.RowsAffected(); ra > 0 {
		// We successfully added the favorite — bump the repo's star_count
		upd := `UPDATE repositories SET star_count = COALESCE(star_count,0) + 1 WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`
		_, _ = m.Store.db.Exec(upd, repoName, owner)
	}
	return nil
}

func (m *RepoManager) RemoveFavorite(user, owner, repoName string) error {
	query := `
	DELETE FROM favorites WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE) AND repo_id = (
	    SELECT id FROM repositories WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)
	)`
	res, err := m.Store.db.Exec(query, user, repoName, owner)
	if err != nil {
		return err
	}
	if ra, _ := res.RowsAffected(); ra > 0 {
		// A favorite was removed — decrement star_count (not below 0)
		upd := `UPDATE repositories SET star_count = CASE WHEN COALESCE(star_count,0) > 0 THEN star_count - 1 ELSE 0 END WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)`
		_, _ = m.Store.db.Exec(upd, repoName, owner)
	}
	return nil
}

func (m *RepoManager) IsFavorite(user, owner, repoName string) (bool, error) {
	var exists int
	query := `
	SELECT EXISTS(SELECT 1 FROM favorites WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE) AND repo_id = (
	    SELECT id FROM repositories WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)
	))`
	if err := m.Store.db.QueryRow(query, user, repoName, owner).Scan(&exists); err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (m *RepoManager) GetFavoritesForUser(username string) ([]map[string]interface{}, error) {
	query := `
	SELECT r.name, u.username, r.download_count, COALESCE(r.star_count,0), r.is_private, r.created_at
	FROM favorites f
	JOIN repositories r ON f.repo_id = r.id
	JOIN users u ON r.user_id = u.id
	WHERE f.user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)
	ORDER BY f.created_at DESC`

	rows, err := m.Store.db.Query(query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []map[string]interface{}
	for rows.Next() {
		var name string
		var owner string
		var downloadCount int
		var starCount int
		var isPrivate int
		var createdAt string
		if err := rows.Scan(&name, &owner, &downloadCount, &starCount, &isPrivate, &createdAt); err != nil {
			continue
		}
		res = append(res, map[string]interface{}{
			"Name":          name,
			"Owner":         owner,
			"DownloadCount": downloadCount,
			"StarCount":     starCount,
			"IsPrivate":     isPrivate == 1,
			"CreatedAt":     createdAt,
		})
	}
	return res, nil
}

// HTTP handler: add favorite (POST)
func (m *RepoManager) HandleAddFavorite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	user, err := m.Store.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" || repo == "" {
		http.Error(w, "Missing parameters", 400)
		return
	}
	if err := m.AddFavorite(user, owner, repo); err != nil {
		log.Printf("ERROR adding favorite: %v", err)
		http.Error(w, "Server error", 500)
		return
	}
	sc := m.GetStarCount(owner, repo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"favorited": true, "star_count": sc})
}

// HTTP handler: remove favorite (POST)
func (m *RepoManager) HandleRemoveFavorite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	user, err := m.Store.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" || repo == "" {
		http.Error(w, "Missing parameters", 400)
		return
	}
	if err := m.RemoveFavorite(user, owner, repo); err != nil {
		log.Printf("ERROR removing favorite: %v", err)
		http.Error(w, "Server error", 500)
		return
	}
	sc := m.GetStarCount(owner, repo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"favorited": false, "star_count": sc})
}
