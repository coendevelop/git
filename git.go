package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
)

func main() {
	// Init Database & Store
	store, err := NewAuthStore("./data/git_service.db")
	if err != nil {
		log.Fatal(err)
	}

	// Init Repo Manager with the Store dependency
	mgr := &RepoManager{
		BaseDir: "./data/repos",
		Store:   store,
	}

	// Registration/Login/Auth routing
	http.HandleFunc("/register", store.HandleRegister)
	http.HandleFunc("/login", store.HandleLogin)
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		tmpl, _ := template.ParseFS(templateFiles, "templates/auth.tmpl")
		tmpl.Execute(w, nil)
	})
	http.HandleFunc("/check-user", store.HandleCheckUser)
	http.HandleFunc("/logout", store.HandleLogout)

	// Dashboard routing
	http.HandleFunc("/", mgr.HandleDashboard) // Todo: show repos/users
	// Example URL: /view/my-project/subdir/main.go
	http.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		// 1. Get user context
		username, err := mgr.Store.GetUserByTokenFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}

		// 2. Split the path: /view/repoName/path/to/file
		pathSegments := strings.Split(strings.TrimPrefix(r.URL.Path, "/view/"), "/")
		if len(pathSegments) < 1 {
			http.Error(w, "Invalid URL", 400)
			return
		}

		repoName := pathSegments[0]
		filePath := strings.Join(pathSegments[1:], "/") // will be empty if at root

		// 3. Delegate to the handler
		mgr.HandleRepoNavigation(w, r, username, repoName, filePath)
	})

	// Start Servers
	go func() {
		fmt.Println("Web UI: http://localhost:8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	config, err := setupSSHConfig(store)
	if err != nil {
		log.Fatalf("Failed to setup SSH: %v", err)
	}

	// Start Listener
	// Note: Port 22 usually requires root/sudo.
	// Consider using 2222 for development.
	addr := "0.0.0.0:2222"
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", err)
	}

	log.Printf("Git SSH server listening on %s...", addr)

	// SSH accept loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go handleSSHConn(conn, config)
	}
}
