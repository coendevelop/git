package main

import (
	"html/template"
	"log"
	"net/http"
)

// Define the data structure for our HTML template
type DashboardData struct {
	Username string
	Repos    []string
}

func (m *RepoManager) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	if m.Store == nil {
		log.Println("Error: RepoManager has no AuthStore assigned!")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		log.Println("Dashboard Redirect: No cookie found") // Debug log
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	username, err := m.Store.GetUserByToken(cookie.Value)
	if err != nil {
		log.Printf("Dashboard Redirect: Token %s not found in DB: %v", cookie.Value, err) // Debug log
		http.Redirect(w, r, "/register", http.StatusSeeOther)
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
