package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Define the data structure for our HTML template
type DashboardData struct {
	Username string
	Repos    []string
}

// HandleDashboard enumerates repositories on disk, applies privacy rules,
// and renders the dashboard template showing all repos, the user's own repos
// and favorites. Sorting and simple filtering are handled here.
func (m *RepoManager) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	// 1. Attempt to get the user, but don't redirect on error
	username, err := m.Store.GetUserByTokenFromRequest(r)
	isLoggedIn := err == nil

	type RepoInfo struct {
		Name          string
		Owner         string
		DownloadCount int
		StarCount     int
		IsPrivate     bool
		CreatedAt     time.Time
		IsFavorite    bool
		HasContent    bool
	}
	var allRepos []RepoInfo
	var myRepos []RepoInfo
	var favorites []RepoInfo

	// 2. Fetch ALL folders from the disk (scanning all user directories)
	userDirs, err := os.ReadDir(m.BaseDir)
	if err == nil {
		for _, uDir := range userDirs {
			if uDir.IsDir() {
				ownerName := uDir.Name()
				userPath := filepath.Join(m.BaseDir, ownerName)

				// Scan this specific user's folder for git repos (bare `.git` and non-bare)
				repos, _ := os.ReadDir(userPath)
				for _, rDir := range repos {
					if !rDir.IsDir() {
						continue
					}
					name := rDir.Name()
					repoName := ""

					if strings.HasSuffix(name, ".git") {
						repoName = strings.TrimSuffix(name, ".git")
					} else {
						// detect non-bare repo via `.git` subdir or HEAD file
						possibleDotGit := filepath.Join(userPath, name, ".git")
						if fi, err := os.Stat(possibleDotGit); err == nil && fi.IsDir() {
							repoName = name
						} else if _, err := os.Stat(filepath.Join(userPath, name, "HEAD")); err == nil {
							repoName = name
						}
					}

					if repoName == "" {
						continue
					}

					// Skip private repos for users who are not the owner
					if isPriv, err := m.IsRepoPrivate(ownerName, repoName); err == nil && isPriv && username != ownerName {
						continue
					}

					// Fetch metadata from DB
					count, createdAtStr, isPrivMeta, starCount, _ := m.GetRepoMeta(ownerName, repoName)
					createdAt := time.Now()
					if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
						createdAt = t
					}

					isFav := false
					if username != "" {
						if fav, err := m.IsFavorite(username, ownerName, repoName); err == nil && fav {
							isFav = true
						}
					}

					// Determine whether the repo has commits/content
					hasContent := m.RepoHasCommits(ownerName, repoName)

					repoInfo := RepoInfo{
						Name:          repoName,
						Owner:         ownerName,
						DownloadCount: count,
						StarCount:     starCount,
						IsPrivate:     isPrivMeta,
						CreatedAt:     createdAt,
						IsFavorite:    isFav,
						HasContent:    hasContent,
					}
					allRepos = append(allRepos, repoInfo)
					if username == ownerName {
						myRepos = append(myRepos, repoInfo)
					}
				}
			}
		}
	}

	// Build favorites list for the logged-in user
	if username != "" {
		if favs, err := m.GetFavoritesForUser(username); err == nil {
			for _, f := range favs {
				createdAt := time.Now()
				if s, ok := f["CreatedAt"].(string); ok {
					if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
						createdAt = t
					}
				}
				favorites = append(favorites, RepoInfo{
					Name:          f["Name"].(string),
					Owner:         f["Owner"].(string),
					DownloadCount: f["DownloadCount"].(int),
					StarCount:     f["StarCount"].(int),
					IsPrivate:     f["IsPrivate"].(bool),
					CreatedAt:     createdAt,
					IsFavorite:    true,
				})
			}
		}
	}

	// Sorting: support sort=downloads|recent|alpha
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "recent"
	}

	sortRepos := func(list []RepoInfo) {
		switch sortKey {
		case "downloads":
			sort.Slice(list, func(i, j int) bool { return list[i].DownloadCount > list[j].DownloadCount })
		case "alpha":
			sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		default: // recent
			sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
		}
	}

	sortRepos(allRepos)
	sortRepos(myRepos)
	// Favorites already returned in recent order from DB

	// 3. Prepare data for the template
	data := map[string]interface{}{
		"Username":   username,
		"IsLoggedIn": isLoggedIn,
		"AllRepos":   allRepos,
		"MyRepos":    myRepos,
		"Favorites":  favorites,
		"SortKey":    sortKey,
	}

	m.renderTemplate(w, "dashboard.tmpl", data)
}
