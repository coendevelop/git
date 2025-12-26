# Git@CoenDevelop

A lightweight, self-hosted Git service built with **Go** and **Bootstrap 5**. This project provides a web-based dashboard for managing repositories and an integrated SSH server for Git operations.

## 🚀 Features

* **Repository Management:** Create and manage bare Git repositories via a clean web UI.
* **Web-Based File Browser:** Explore repository trees, view code with monospaced styling, and track the latest commit metadata.
* **Integrated Auth:** Dynamic login/registration flow that adapts to existing users.
* **SSH Access:** Support for standard Git CLI operations over SSH (configured for port `2222`).
* **Responsive UI:** Fully themed with Bootstrap 5.3, featuring interactive cards and modals.

## 🛠️ Tech Stack

* **Backend:** [Go (Golang)](https://golang.org/)
* **Git Logic:** [go-git](https://github.com/go-git/go-git)
* **Frontend:** HTML5, Bootstrap 5.3, JavaScript
* **Storage:** Local filesystem for bare repositories.

## 📋 Prerequisites

* Go 1.21+
* Git installed on the host system.
* Port `2222` (SSH) and `8080` (HTTP) open for traffic.

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/coendevelop/git.git](https://github.com/coendevelop/git.git)
   cd git
