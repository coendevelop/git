package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
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
	// Future: http.HandleFunc("/repo/", mgr.HandleRepoView)

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
