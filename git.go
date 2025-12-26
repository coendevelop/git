package main

import (
	"fmt"
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

	// 2. CORRECTED: Use the constructor to load templates
	mgr, err := NewRepoManager("data/repos", store)
	if err != nil {
		log.Fatalf("Failed to initialize Repo Manager: %v", err)
	}

	// License link

	// Registration/Login/Auth routing
	http.HandleFunc("/register", store.HandleRegister)
	http.HandleFunc("/login", store.HandleLogin)
	// Use the mgr.renderTemplate to stay consistent with the cache
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// Note: We use the base name "auth.tmpl" as seen in your logs
		mgr.renderTemplate(w, "auth.tmpl", nil)
	})
	http.HandleFunc("/check-user", store.HandleCheckUser)
	http.HandleFunc("/logout", store.HandleLogout)

	// User routing
	http.HandleFunc("/", mgr.HandleDashboard) // Todo: show repos/users
	// Example URL: /view/my-project/subdir/main.go
	// Note the trailing slash! This allows /view/user/repo to work.
	http.HandleFunc("/view/{path...}", mgr.HandleView)
	http.HandleFunc("/download/view/{path...}", mgr.HandleDownloadZip)
	http.HandleFunc("/create-repo", mgr.HandleCreateRepo)

	// Start Servers
	go func() {
		log.Println("Web UI starting...")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()
	fmt.Println("Git@CoenDevelop")
	fmt.Println("This software is licensed with the GNU-GPLv3.")
	fmt.Println("For more information, see http://git.coendevelop.org/license")
	fmt.Println("Web UI: http://localhost:8080")

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
