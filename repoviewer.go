package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Define the data structure for our HTML template
type DashboardData struct {
	Username string
	Repos    []string
}

func (m *RepoManager) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	// 1. Attempt to get the user, but don't redirect on error
	username, err := m.Store.GetUserByTokenFromRequest(r)
	isLoggedIn := err == nil

	type RepoInfo struct {
		Name  string
		Owner string
	}
	var allRepos []RepoInfo

	// 2. Fetch ALL folders from the disk (scanning all user directories)
	userDirs, err := os.ReadDir(m.BaseDir)
	if err == nil {
		for _, uDir := range userDirs {
			if uDir.IsDir() {
				ownerName := uDir.Name()
				userPath := filepath.Join(m.BaseDir, ownerName)

				// Scan this specific user's folder for .git repos
				repos, _ := os.ReadDir(userPath)
				for _, rDir := range repos {
					if rDir.IsDir() && strings.HasSuffix(rDir.Name(), ".git") {
						allRepos = append(allRepos, RepoInfo{
							Name:  strings.TrimSuffix(rDir.Name(), ".git"),
							Owner: ownerName,
						})
					}
				}
			}
		}
	}

	// 3. Prepare data for the template
	data := map[string]interface{}{
		"Username":   username,
		"IsLoggedIn": isLoggedIn,
		"Repos":      allRepos,
	}

	m.renderTemplate(w, "dashboard.tmpl", data)
}
