package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// parseGitCommand takes the raw exec payload from ssh (e.g. "git-upload-pack 'user/repo.git'")
// and returns the git subcommand (git-upload-pack, git-receive-pack, etc.) and the
// repository path as separate strings. If the payload doesn't include a path,
// the second return value is empty.
func parseGitCommand(payload string) (string, string) {
	// The payload looks like: git-upload-pack 'user/repo.git'
	// 1. Split by space
	parts := strings.SplitN(strings.TrimSpace(payload), " ", 2)
	if len(parts) < 2 {
		return parts[0], ""
	}

	gitCmd := parts[0]
	// 2. Remove the single quotes around the path
	repoPath := strings.Trim(parts[1], "'")

	return gitCmd, repoPath
}

// generateHostKey creates a new RSA host key and writes it in PEM format to
// `path` with 0600 permissions. Used when no host key exists on disk.
func generateHostKey(path string) error {
	// 1. Generate the private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 2. Encode to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// 3. Create the file
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, privateKeyPEM)
}

// setupSSHConfig constructs an ssh.ServerConfig that authenticates incoming
// public-key connections by mapping the provided public key to an application
// username (via AuthStore.GetUserByKey). If no host key exists, it will be
// generated on disk and loaded.
func setupSSHConfig(store *AuthStore) (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			username, err := store.GetUserByKey(key) // This still uses the key-to-user mapping
			if err != nil {
				return nil, err
			}
			return &ssh.Permissions{
				Extensions: map[string]string{"username": username},
			}, nil
		},
	}

	keyPath := "./data/host_key"

	// TODO: If Host Key does not exist, create it
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Println("Host key not found. Generating new RSA key...")
		if err := generateHostKey(keyPath); err != nil {
			return nil, fmt.Errorf("could not generate host key: %w", err)
		}
	}

	// Now load it as before
	privateBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key: %w", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}

	config.AddHostKey(private)
	return config, nil
}

// handleSSHConn accepts a raw net.Conn, establishes the SSH server
// handshake and handles incoming session channels. Exec requests are parsed
// and authorized by checking that the requested repo path begins with the
// authenticated username. The implementation runs git subprocesses and
// pipes stdin/stdout/stderr between the SSH channel and the process.
func handleSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	// Note: Always handle the error from NewServerConn in production!
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}

	authenticatedUser := sConn.Permissions.Extensions["username"]
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, _ := newChannel.Accept()

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "exec":
					// FIX 1 & 2: Define payload and strip the first 4 bytes
					payload := string(req.Payload[4:])
					gitCmd, repoPath := parseGitCommand(payload)

					validCommands := map[string]bool{
						"git-upload-pack":    true,
						"git-receive-pack":   true,
						"git-upload-archive": true,
					}

					if !validCommands[gitCmd] {
						fmt.Fprintf(channel.Stderr(), "Invalid command: %s\n", gitCmd)
						req.Reply(false, nil) // Tell the client the request failed
						channel.Close()
						return
					}

					if !strings.HasPrefix(repoPath, authenticatedUser+"/") {
						fmt.Fprintf(channel.Stderr(), "Access Denied for user: %s\n", authenticatedUser)
						req.Reply(false, nil)
						channel.Close()
						return
					}

					// Run the command
					fullPath := filepath.Join("./data/repos/", repoPath)
					cmd := exec.Command(gitCmd, fullPath)

					stdout, _ := cmd.StdoutPipe()
					stdin, _ := cmd.StdinPipe()
					stderr, _ := cmd.StderrPipe()

					if err := cmd.Start(); err != nil {
						req.Reply(false, nil)
						channel.Close()
						return
					}

					// Tell the client we accepted the exec request
					req.Reply(true, nil)

					// Data piping
					go io.Copy(channel, stdout)
					go io.Copy(channel.Stderr(), stderr)
					go io.Copy(stdin, channel)

					cmd.Wait()
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()

				default:
					// Reply false to unknown request types (like 'pty-req')
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}
