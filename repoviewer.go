package main

import (
	"html/template"
	"net/http"
)

// Define the data structure for our HTML template
type DashboardData struct {
	Username string
	Repos    []string
}

func (m *RepoManager) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	username, err := m.getAuthenticatedUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	repos, err := m.ListRepos(username)
	if err != nil {
		http.Error(w, "Failed to list repos", http.StatusInternalServerError)
		return
	}

	data := DashboardData{Username: username, Repos: repos}
	tmpl, _ := template.ParseFS(templateFiles, "templates/dashboard.tmpl")
	tmpl.Execute(w, data)
}
