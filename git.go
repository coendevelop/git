package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

//go:embed templates/*
var templateFiles embed.FS

// App is the central controller holding DB connection and config.
type App struct {
	DB        *sql.DB
	BaseDir   string
	Templates *template.Template
}

// FileInfo represents a file entry for the UI.
type FileInfo struct {
	Name  string
	IsURL bool
	Size  int64
}

type CommitInfo struct {
	Hash         string
	ShortHash    string
	Author       string
	Email        string
	When         string
	Message      string
	MessageShort string
}

const initSchema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_private INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    star_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_data TEXT NOT NULL UNIQUE, 
    label TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    repo_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(repo_id) REFERENCES repositories(id) ON DELETE CASCADE,
    UNIQUE(user_id, repo_id)
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_repos_owner_name ON repositories(user_id, name);
CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id);
`

// --- Initialization ---

func NewApp(dbPath, repoDir string) (*App, error) {
	// 1. Setup Repo Directory
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create repo dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db dir: %w", err)
	}

	// 2. Setup Database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(initSchema); err != nil {
		return nil, fmt.Errorf("schema init failed: %w", err)
	}
	// Run migrations (columns added later)
	migrateDB(db)

	// 3. Setup Templates
	tmpl := template.New("")
	// Walk embedded FS to parse templates
	err = fsWalk(templateFiles, "templates", func(path string, isDir bool) error {
		if !isDir && strings.HasSuffix(path, ".tmpl") {
			data, err := templateFiles.ReadFile(path)
			if err != nil {
				return err
			}
			name := strings.TrimPrefix(path, "templates/")
			name = filepath.ToSlash(name)
			if _, err := tmpl.New(name).Parse(string(data)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("template load failed: %w", err)
	}

	return &App{
		DB:        db,
		BaseDir:   repoDir,
		Templates: tmpl,
	}, nil
}

func migrateDB(db *sql.DB) {
	// Minimal migration logic to ensure columns exist
	cols := []string{"is_private", "star_count"}
	for _, col := range cols {
		// Attempt to add column, ignore error if it exists
		_, _ = db.Exec(fmt.Sprintf("ALTER TABLE repositories ADD COLUMN %s INTEGER DEFAULT 0", col))
	}
}

// Helper to walk embed.FS since it doesn't have a native Walk
func fsWalk(fs embed.FS, dir string, callback func(path string, isDir bool) error) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if err := callback(path, entry.IsDir()); err != nil {
			return err
		}
		if entry.IsDir() {
			if err := fsWalk(fs, path, callback); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- Main Entry ---

func main() {
	app, err := NewApp("./data/git_service.db", "./data/repos")
	if err != nil {
		log.Fatal(err)
	}

	// HTTP Routing
	http.HandleFunc("/register", app.HandleRegister)
	http.HandleFunc("/login", app.HandleLogin)
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		app.render(w, "auth.tmpl", nil)
	})
	http.HandleFunc("/check-user", app.HandleCheckUser)
	http.HandleFunc("/logout", app.HandleLogout)

	http.HandleFunc("/", app.HandleDashboard)
	http.HandleFunc("/download/view/", app.HandleDownloadZip)
	http.HandleFunc("/upload", app.HandleUpload)
	http.HandleFunc("/edit", app.HandleEdit)
	http.HandleFunc("/create-repo", app.HandleCreateRepo)
	http.HandleFunc("/favorite/add", app.HandleAddFavorite)
	http.HandleFunc("/favorite/remove", app.HandleRemoveFavorite)
	http.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		app.HandleView(w, r)
	})

	// Start HTTP Server
	go func() {
		log.Println("Web UI: http://localhost:8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// Start SSH Server
	startSSHServer(app)
}

// --- Helper: Rendering ---

func (a *App) render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.Templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("RENDER ERROR %s: %v", name, err)
		http.Error(w, "Template error", 500)
	}
}

// --- Authentication & Users ---

func (a *App) GetUserByTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	var username string
	query := `SELECT users.username FROM users 
			  JOIN sessions ON users.id = sessions.user_id 
			  WHERE sessions.token = ? AND sessions.expires_at > datetime('now')`
	if err := a.DB.QueryRow(query, cookie.Value).Scan(&username); err != nil {
		return "", err
	}
	return username, nil
}

func (a *App) CreateSession(w http.ResponseWriter, username string) {
	var userID int
	if err := a.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		return
	}

	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)

	a.DB.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, userID, time.Now().Add(24*time.Hour))

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	u, p := r.FormValue("username"), r.FormValue("password")

	// Basic validation
	validUser := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if len(u) < 3 || len(u) > 32 || !validUser.MatchString(u) {
		http.Error(w, "Invalid username", 400)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(p), 10)
	_, err := a.DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", u, string(hash))

	if err != nil && !strings.Contains(err.Error(), "UNIQUE") {
		http.Error(w, "Registration failed", 500)
		return
	}

	a.CreateSession(w, u)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (a *App) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	u, p := r.FormValue("username"), r.FormValue("password")

	var hash string
	err := a.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", u).Scan(&hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	a.CreateSession(w, u)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (a *App) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		a.DB.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session_token", MaxAge: -1})
	http.Redirect(w, r, "/auth", http.StatusSeeOther)
}

func (a *App) HandleCheckUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	var exists bool
	a.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&exists)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"exists": %v}`, exists)
}

// --- Repository Management ---

func (a *App) HandleCreateRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	user, err := a.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	repoName := r.FormValue("name")
	isPriv := r.FormValue("is_private") == "1"
	autoInit := r.FormValue("init_readme") == "1"

	// Ensure the user's directory exists
	userDir := filepath.Join(a.BaseDir, user)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		http.Error(w, "Failed to create user directory", 500)
		return
	}

	repoPath := filepath.Join(userDir, repoName+".git")

	// 1. Initialize the repository
	if autoInit {
		// Initialize a non-bare repository to allow for a worktree and initial commit
		gitRepo, err := git.PlainInit(repoPath, false)
		if err != nil {
			http.Error(w, "Failed to init repo with README", 500)
			return
		}

		wt, err := gitRepo.Worktree()
		if err != nil {
			http.Error(w, "Failed to get worktree", 500)
			return
		}

		// Create the initial README.md
		readmePath := filepath.Join(repoPath, "README.md")
		readmeContent := fmt.Sprintf("# %s\n\nInitial repository setup by %s.", repoName, user)
		if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
			http.Error(w, "Failed to write README", 500)
			return
		}

		// Commit the README
		if _, err := wt.Add("README.md"); err != nil {
			http.Error(w, "Failed to stage README", 500)
			return
		}

		_, err = wt.Commit("Initial commit: add README.md", &git.CommitOptions{
			Author: &object.Signature{
				Name:  user,
				Email: user + "@coendevelop.org",
				When:  time.Now(),
			},
		})
		if err != nil {
			http.Error(w, "Failed to create initial commit", 500)
			return
		}
	} else {
		// Initialize a standard bare repository for remote pushing
		_, err = git.PlainInit(repoPath, true)
		if err != nil {
			http.Error(w, "Failed to init bare repo", 500)
			return
		}
	}

	// 2. Insert repository record into the DB
	privInt := 0
	if isPriv {
		privInt = 1
	}

	_, err = a.DB.Exec(`INSERT INTO repositories (user_id, name, description, is_private)
		VALUES ((SELECT id FROM users WHERE username = ? COLLATE NOCASE), ?, ?, ?)`,
		user, repoName, "No description", privInt)

	if err != nil {
		// If DB insertion fails, we should ideally clean up the disk,
		// but for now we'll just report the error.
		http.Error(w, "Database error: "+err.Error(), 500)
		return
	}

	// Redirect to the repository view - the main branch should now exist if autoInit was true
	http.Redirect(w, r, "/view/"+user+"/"+repoName+"/main/", http.StatusSeeOther)
}

func (a *App) HandleCommits(w http.ResponseWriter, r *http.Request) {
	// Path format: /view/{user}/{repo}/commits/{branch}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/view/"), "/"), "/")
	if len(parts) < 4 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := parts[0]
	repoName := parts[1]
	// parts[2] is literally the string "commits"
	branchName := parts[3]

	// Privacy Check
	viewer, _ := a.GetUserByTokenFromRequest(r)
	var isPriv int
	err := a.DB.QueryRow(`SELECT is_private FROM repositories WHERE name=? 
		AND user_id=(SELECT id FROM users WHERE username=?)`, repoName, username).Scan(&isPriv)
	if (err != nil) || (isPriv == 1 && viewer != username) {
		http.Error(w, "Not found", 404)
		return
	}

	repoPath := filepath.Join(a.BaseDir, username, repoName+".git")
	gitRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}

	// Resolve the branch to a hash
	hash, err := gitRepo.ResolveRevision(plumbing.Revision(branchName))
	if err != nil {
		// Fallback to HEAD if branch doesn't exist
		hash, _ = gitRepo.ResolveRevision(plumbing.Revision("HEAD"))
	}

	// Get the commit log
	cIter, err := gitRepo.Log(&git.LogOptions{From: *hash})
	if err != nil {
		http.Error(w, "Failed to retrieve commits", 500)
		return
	}

	var commits []CommitInfo
	err = cIter.ForEach(func(c *object.Commit) error {
		// Limit to last 50 commits for performance; can add pagination later
		if len(commits) >= 50 {
			return fmt.Errorf("limit reached")
		}

		msgLines := strings.Split(strings.TrimSpace(c.Message), "\n")
		shortMsg := msgLines[0]
		if len(shortMsg) > 80 {
			shortMsg = shortMsg[:77] + "..."
		}

		commits = append(commits, CommitInfo{
			Hash:         c.Hash.String(),
			ShortHash:    c.Hash.String()[:7],
			Author:       c.Author.Name,
			Email:        c.Author.Email,
			When:         c.Author.When.Format("Jan 02, 2006 15:04"),
			Message:      c.Message,
			MessageShort: shortMsg,
		})
		return nil
	})

	// Data for template
	data := map[string]interface{}{
		"Owner":         username,
		"RepoName":      repoName,
		"CurrentBranch": branchName,
		"Commits":       commits,
		"IsLoggedIn":    viewer != "",
		"Username":      viewer,
	}

	// We'll need a new template for this: repo_commits.tmpl
	a.render(w, "repo_commits.tmpl", data)
}

func (a *App) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	currUser, err := a.GetUserByTokenFromRequest(r)
	isLoggedIn := err == nil

	type RepoInfo struct {
		Name, Owner                       string
		DownloadCount, StarCount          int
		IsPrivate, IsFavorite, HasContent bool
		CreatedAt                         time.Time
	}

	var allRepos, myRepos, favorites []RepoInfo

	// Scan Disk
	users, _ := os.ReadDir(a.BaseDir)
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		owner := u.Name()
		repos, _ := os.ReadDir(filepath.Join(a.BaseDir, owner))
		for _, repoDir := range repos {
			name := repoDir.Name()
			if !strings.HasSuffix(name, ".git") && !strings.Contains(name, ".") {
				// Handle non-bare checkout if needed, simplified here to just git suffix check
				continue
			}
			repoName := strings.TrimSuffix(name, ".git")

			// Privacy Check
			var isPrivInt int
			var dlCount, starCount int
			var createdStr string
			err := a.DB.QueryRow(`SELECT is_private, download_count, COALESCE(star_count,0), created_at 
				FROM repositories WHERE name=? AND user_id=(SELECT id FROM users WHERE username=?)`,
				repoName, owner).Scan(&isPrivInt, &dlCount, &starCount, &createdStr)

			if err != nil {
				continue
			} // Not in DB

			isPriv := isPrivInt == 1
			if isPriv && currUser != owner {
				continue
			}

			// Check Content
			hasContent := false
			if r, err := git.PlainOpen(filepath.Join(a.BaseDir, owner, name)); err == nil {
				if _, err := r.Head(); err == nil {
					hasContent = true
				}
			}

			// Check Favorite
			isFav := false
			if isLoggedIn {
				var exists int
				a.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM favorites f JOIN repositories r ON f.repo_id = r.id 
					WHERE f.user_id=(SELECT id FROM users WHERE username=?) 
					AND r.name=? AND r.user_id=(SELECT id FROM users WHERE username=?))`,
					currUser, repoName, owner).Scan(&exists)
				isFav = exists == 1
			}

			ts, _ := time.Parse("2006-01-02 15:04:05", createdStr)

			info := RepoInfo{repoName, owner, dlCount, starCount, isPriv, isFav, hasContent, ts}
			allRepos = append(allRepos, info)
			if owner == currUser {
				myRepos = append(myRepos, info)
			}
		}
	}

	// Fetch Favorites
	if isLoggedIn {
		rows, _ := a.DB.Query(`SELECT r.name, u.username, r.download_count, r.star_count, r.is_private 
			FROM favorites f JOIN repositories r ON f.repo_id=r.id JOIN users u ON r.user_id=u.id 
			WHERE f.user_id=(SELECT id FROM users WHERE username=?)`, currUser)
		defer rows.Close()
		for rows.Next() {
			var ri RepoInfo
			var privInt int
			rows.Scan(&ri.Name, &ri.Owner, &ri.DownloadCount, &ri.StarCount, &privInt)
			ri.IsPrivate = privInt == 1
			ri.IsFavorite = true
			favorites = append(favorites, ri)
		}
	}

	// Sort (default recent)
	sorter := func(l []RepoInfo) {
		sort.Slice(l, func(i, j int) bool { return l[i].CreatedAt.After(l[j].CreatedAt) })
	}
	sorter(allRepos)
	sorter(myRepos)

	a.render(w, "dashboard.tmpl", map[string]interface{}{
		"Username": currUser, "IsLoggedIn": isLoggedIn,
		"AllRepos": allRepos, "MyRepos": myRepos, "Favorites": favorites,
	})
}

func (a *App) HandleView(w http.ResponseWriter, r *http.Request) {
	// If the user is submitting an edit form, route to the HandleEdit logic
	if r.Method == http.MethodPost {
		a.HandleEdit(w, r)
		return
	}

	// Path parsing: /view/{user}/{repo}/{mode}/{branch}/{path...}
	rawPath := strings.TrimPrefix(r.URL.Path, "/view/")
	parts := strings.Split(strings.Trim(rawPath, "/"), "/")

	if len(parts) < 2 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username, repoName := parts[0], parts[1]

	isCommitsView := false
	isDiffView := false
	targetHash := ""
	branchName := "main"
	remainingParts := parts[2:]

	// Route detection (Commits vs Diff vs Standard View)
	if len(remainingParts) > 0 {
		if remainingParts[0] == "commits" {
			isCommitsView = true
			remainingParts = remainingParts[1:]
		} else if remainingParts[0] == "commit" {
			isDiffView = true
			if len(remainingParts) > 1 {
				targetHash = remainingParts[1]
			}
			remainingParts = remainingParts[1:]
		}
	}

	if len(remainingParts) > 0 && !isDiffView {
		branchName = remainingParts[0]
		remainingParts = remainingParts[1:]
	}

	path := strings.Join(remainingParts, "/")

	// Privacy and Access Check
	viewer, _ := a.GetUserByTokenFromRequest(r)
	var isPriv int
	a.DB.QueryRow(`SELECT is_private FROM repositories WHERE name=? 
		AND user_id=(SELECT id FROM users WHERE username=?)`, repoName, username).Scan(&isPriv)
	if isPriv == 1 && viewer != username {
		http.Error(w, "Not found", 404)
		return
	}

	repoPath := filepath.Join(a.BaseDir, username, repoName+".git")
	gitRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}

	// Setup Base View Data
	data := map[string]interface{}{
		"Owner":         username,
		"RepoName":      repoName,
		"CurrentBranch": branchName,
		"SSHAddr":       r.Host,
		"CurrentPath":   path,
		"IsCommitsView": isCommitsView,
		"IsDiffView":    isDiffView,
		"IsLoggedIn":    viewer != "",
		"Username":      viewer,
	}

	// Resolve Revision (Branch or Hash)
	hash, err := gitRepo.ResolveRevision(plumbing.Revision(branchName))
	if err != nil {
		hash, err = gitRepo.ResolveRevision(plumbing.Revision("HEAD"))
		if err != nil {
			data["IsEmpty"] = true
			a.render(w, "repo_view.tmpl", data)
			return
		}
	}

	// Fetch Repository Metadata (Stars/Downloads)
	var dl, star int
	a.DB.QueryRow(`SELECT download_count, star_count FROM repositories 
		WHERE name=? AND user_id=(SELECT id FROM users WHERE username=?)`, repoName, username).Scan(&dl, &star)
	data["DownloadCount"] = dl
	data["StarCount"] = star

	// --- LOGIC FOR DIFF VIEW ---
	if isDiffView {
		cHash := plumbing.NewHash(targetHash)
		commit, _ := gitRepo.CommitObject(cHash)
		parent, _ := commit.Parent(0)

		currentTree, _ := commit.Tree()
		var patch *object.Patch

		if parent != nil {
			parentTree, _ := parent.Tree()
			changes, _ := parentTree.Diff(currentTree)
			patch, _ = changes.Patch()
		} else {
			changes, _ := (&object.Tree{}).Diff(currentTree)
			patch, _ = changes.Patch()
		}

		data["Diff"] = patch.String()
		data["SelectedCommit"] = map[string]interface{}{
			"Hash":    commit.Hash.String(),
			"Author":  commit.Author.Name,
			"Date":    commit.Author.When.Format("Jan 02, 2006 15:04"),
			"Message": commit.Message,
		}
		data["LastCommit"] = map[string]interface{}{
			"Message": commit.Message,
			"Author":  commit.Author.Name,
			"Date":    commit.Author.When.Format("Jan 02, 2006"),
		}

		a.render(w, "repo_view.tmpl", data)
		return
	}

	// Standard View Logic (File list or Content)
	mainCommit, _ := gitRepo.CommitObject(*hash)
	data["LastCommit"] = map[string]interface{}{
		"Message": mainCommit.Message,
		"Author":  mainCommit.Author.Name,
		"Date":    mainCommit.Author.When.Format("Jan 02, 2006"),
	}

	// --- LOGIC FOR COMMITS LIST (PAGINATED) ---
	if isCommitsView {
		pageSize := 20
		pageStr := r.URL.Query().Get("page")
		page := 1
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}

		cIter, _ := gitRepo.Log(&git.LogOptions{From: *hash})
		var commits []map[string]interface{}

		count := 0
		skip := (page - 1) * pageSize
		hasMore := false

		err = cIter.ForEach(func(c *object.Commit) error {
			if count < skip {
				count++
				return nil
			}
			if len(commits) >= pageSize {
				hasMore = true
				return fmt.Errorf("limit reached")
			}

			msgLines := strings.Split(strings.TrimSpace(c.Message), "\n")
			commits = append(commits, map[string]interface{}{
				"Hash":         c.Hash.String(),
				"ShortHash":    c.Hash.String()[:7],
				"Author":       c.Author.Name,
				"Date":         c.Author.When.Format("Jan 02, 2006 15:04"),
				"MessageShort": msgLines[0],
			})
			count++
			return nil
		})

		data["Commits"] = commits
		data["CurrentPage"] = page
		if page > 1 {
			data["PrevPage"] = page - 1
		}
		if hasMore {
			data["NextPage"] = page + 1
		}
	} else {
		// --- LOGIC FOR FILE BROWSER / FILE VIEWER ---
		tree, _ := mainCommit.Tree()
		if path != "" {
			entry, err := tree.FindEntry(path)
			if err != nil {
				http.Redirect(w, r, "/view/"+username+"/"+repoName+"/"+branchName+"/", http.StatusSeeOther)
				return
			}
			if entry.Mode.IsFile() {
				file, _ := tree.File(path)
				content, _ := file.Contents()
				data["IsFile"] = true
				data["Content"] = content
				data["FileName"] = entry.Name
				// FIX: Set CurrentPath to the directory portion only to avoid path duplication
				dir := filepath.Dir(path)
				if dir == "." {
					data["CurrentPath"] = ""
				} else {
					data["CurrentPath"] = dir
				}
				data["Extension"] = strings.TrimPrefix(filepath.Ext(entry.Name), ".")
			} else {
				subTree, _ := tree.Tree(path)
				var files []FileInfo
				for _, ent := range subTree.Entries {
					var size int64
					if ent.Mode.IsFile() {
						f, _ := subTree.File(ent.Name)
						size = f.Size
					}
					files = append(files, FileInfo{Name: ent.Name, IsURL: !ent.Mode.IsFile(), Size: size})
				}
				data["Files"] = files
			}
		} else {
			// Root Directory Listing
			var files []FileInfo
			for _, ent := range tree.Entries {
				var size int64
				if ent.Mode.IsFile() {
					f, _ := tree.File(ent.Name)
					size = f.Size
				}
				files = append(files, FileInfo{Name: ent.Name, IsURL: !ent.Mode.IsFile(), Size: size})
			}
			data["Files"] = files
		}
	}

	a.render(w, "repo_view.tmpl", data)
}

func (a *App) HandleDownloadZip(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/download/view/"), "/"), "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path", 400)
		return
	}

	username, repo, branch := parts[0], parts[1], parts[2]

	// Privacy
	viewer, _ := a.GetUserByTokenFromRequest(r)
	var isPriv int
	a.DB.QueryRow(`SELECT is_private FROM repositories WHERE name=? AND user_id=(SELECT id FROM users WHERE username=?)`, repo, username).Scan(&isPriv)
	if isPriv == 1 && viewer != username {
		http.Error(w, "Forbidden", 403)
		return
	}

	rPath := filepath.Join(a.BaseDir, username, repo+".git")
	gr, err := git.PlainOpen(rPath)
	if err != nil {
		http.Error(w, "Repo not found", 404)
		return
	}

	ref, _ := gr.ResolveRevision(plumbing.Revision(branch))
	commit, _ := gr.CommitObject(*ref)
	tree, _ := commit.Tree()

	// Increment Counter
	a.DB.Exec(`UPDATE repositories SET download_count = download_count + 1 
		WHERE name=? AND user_id=(SELECT id FROM users WHERE username=?)`, repo, username)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s.zip", repo, branch))

	zw := zip.NewWriter(w)
	defer zw.Close()

	tree.Files().ForEach(func(f *object.File) error {
		writer, _ := zw.Create(f.Name)
		reader, _ := f.Reader()
		defer reader.Close()
		io.Copy(writer, reader)
		return nil
	})
}

// HandleUpload handles file uploads to a repository's current directory.
func (a *App) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	user, err := a.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	// Parse the multipart form (10MB limit)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large", 400)
		return
	}

	owner := r.FormValue("owner")
	repoName := r.FormValue("repo")
	path := r.FormValue("path")

	if user != owner {
		http.Error(w, "Unauthorized", 403)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file", 400)
		return
	}
	defer file.Close()

	repoPath := filepath.Join(a.BaseDir, owner, repoName+".git")
	gitRepo, _ := git.PlainOpen(repoPath)
	wt, _ := gitRepo.Worktree()

	// Save file to worktree
	dstPath := filepath.Join(repoPath, path, header.Filename)
	dst, _ := os.Create(dstPath)
	defer dst.Close()
	io.Copy(dst, file)

	// Commit changes - Corrected CommitOptions usage
	wt.Add(filepath.Join(path, header.Filename))
	_, err = wt.Commit("Upload "+header.Filename, &git.CommitOptions{
		Author: &object.Signature{
			Name:  user,
			Email: user + "@coendevelop.org",
			When:  time.Now(),
		},
	})

	if err != nil {
		http.Error(w, "Commit failed: "+err.Error(), 500)
		return
	}

	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

// HandleEdit saves changes made to an existing file via the web editor.
func (a *App) HandleEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authentication Check
	user, err := a.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	// 2. Parse Form Data
	owner := r.FormValue("owner")
	repoName := r.FormValue("repo")
	filePath := r.FormValue("path") // This is the relative path from the repo root
	content := r.FormValue("content")

	// Security: Ensure the logged-in user owns the repository
	if user != owner {
		http.Error(w, "Unauthorized to edit this repository", http.StatusUnauthorized)
		return
	}

	// 3. Open the Repository
	repoPath := filepath.Join(a.BaseDir, owner, repoName+".git")
	gitRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}

	wt, err := gitRepo.Worktree()
	if err != nil {
		http.Error(w, "Worktree not available (ensure repo is not bare)", 500)
		return
	}

	// 4. Write the new content to the file
	// FIX: Use the filePath directly relative to the repoPath
	fullPath := filepath.Join(repoPath, filePath)

	// Ensure the directory exists (in case of new files in subdirectories)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		http.Error(w, "Failed to create directory: "+err.Error(), 500)
		return
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		http.Error(w, "Failed to write file: "+err.Error(), 500)
		return
	}

	// 5. Commit the changes
	if _, err := wt.Add(filePath); err != nil {
		http.Error(w, "Failed to stage changes: "+err.Error(), 500)
		return
	}

	_, err = wt.Commit("Update "+filepath.Base(filePath)+" via Web Editor", &git.CommitOptions{
		Author: &object.Signature{
			Name:  user,
			Email: user + "@coendevelop.org",
			When:  time.Now(),
		},
	})
	if err != nil {
		http.Error(w, "Failed to commit changes: "+err.Error(), 500)
		return
	}

	// 6. Redirect back to the file view
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// --- Favorites ---

func (a *App) toggleFavorite(w http.ResponseWriter, r *http.Request, add bool) {
	user, err := a.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}

	owner, repo := r.FormValue("owner"), r.FormValue("repo")

	repoIDQuery := `(SELECT id FROM repositories WHERE name = ? AND user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE))`
	userIDQuery := `(SELECT id FROM users WHERE username = ? COLLATE NOCASE)`

	if add {
		a.DB.Exec(`INSERT OR IGNORE INTO favorites (user_id, repo_id) VALUES (`+userIDQuery+`, `+repoIDQuery+`)`, user, repo, owner)
		a.DB.Exec(`UPDATE repositories SET star_count = COALESCE(star_count,0) + 1 WHERE name=? AND user_id=`+userIDQuery, repo, owner)
	} else {
		a.DB.Exec(`DELETE FROM favorites WHERE user_id=`+userIDQuery+` AND repo_id=`+repoIDQuery, user, repo, owner)
		a.DB.Exec(`UPDATE repositories SET star_count = MAX(0, COALESCE(star_count,0) - 1) WHERE name=? AND user_id=`+userIDQuery, repo, owner)
	}

	var count int
	a.DB.QueryRow(`SELECT star_count FROM repositories WHERE name=? AND user_id=`+userIDQuery, repo, owner).Scan(&count)

	json.NewEncoder(w).Encode(map[string]interface{}{"favorited": add, "star_count": count})
}

func (a *App) HandleAddFavorite(w http.ResponseWriter, r *http.Request) { a.toggleFavorite(w, r, true) }
func (a *App) HandleRemoveFavorite(w http.ResponseWriter, r *http.Request) {
	a.toggleFavorite(w, r, false)
}

// --- SSH Server ---

func startSSHServer(app *App) {
	// Config
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Check DB for Key
			incoming := string(ssh.MarshalAuthorizedKey(key))
			var username string
			err := app.DB.QueryRow(`SELECT u.username FROM users u JOIN public_keys k ON u.id=k.user_id 
				WHERE k.key_data = ?`, incoming).Scan(&username)
			if err != nil {
				return nil, err
			}
			return &ssh.Permissions{Extensions: map[string]string{"username": username}}, nil
		},
	}

	// Host Key
	keyPath := "./data/host_key"
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		f, _ := os.Create(keyPath)
		pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		f.Close()
	}
	bytes, _ := os.ReadFile(keyPath)
	pKey, _ := ssh.ParsePrivateKey(bytes)
	config.AddHostKey(pKey)

	// Listen
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("SSH Server: 0.0.0.0:2222")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSSHConn(conn, config)
	}
}

func handleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}

	user := sConn.Permissions.Extensions["username"]
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		channel, requests, _ := newChannel.Accept()

		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "exec" {
					payload := string(req.Payload[4:])
					parts := strings.SplitN(strings.TrimSpace(payload), " ", 2)
					cmd, path := parts[0], strings.Trim(parts[1], "'")

					// Validate Command & Access
					valid := map[string]bool{"git-upload-pack": true, "git-receive-pack": true}
					if !valid[cmd] || !strings.HasPrefix(path, user+"/") {
						req.Reply(false, nil)
						channel.Close()
						return
					}

					// Execute Git
					gCmd := exec.Command(cmd, filepath.Join("./data/repos", path))
					stdout, _ := gCmd.StdoutPipe()
					stderr, _ := gCmd.StderrPipe()
					stdin, _ := gCmd.StdinPipe()

					gCmd.Start()
					req.Reply(true, nil)

					go io.Copy(channel, stdout)
					go io.Copy(channel.Stderr(), stderr)
					go io.Copy(stdin, channel)

					gCmd.Wait()
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()
					return
				}
				req.Reply(false, nil)
			}
		}(requests)
	}
}
