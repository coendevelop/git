package main

import (
	"log"
	"net/http"
)

// Define the data structure for our HTML template
type DashboardData struct {
	Username string
	Repos    []string
}

func (m *RepoManager) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	username, err := m.Store.GetUserByTokenFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	// Fetch the actual folders from the disk
	repos, err := m.ListUserRepos(username)
	if err != nil {
		log.Printf("Error listing repos for %s: %v", username, err)
	}

	data := map[string]interface{}{
		"Username": username,
		"Repos":    repos,
	}

	m.renderTemplate(w, "dashboard.tmpl", data)
}
