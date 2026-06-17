package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"webattack/pkg/brute"
	"webattack/pkg/csrfssrf"
	"webattack/pkg/httpclient"
	"webattack/pkg/scanner"
	"webattack/pkg/shell"
	"webattack/pkg/sqli"
	"webattack/pkg/stress"
	"webattack/pkg/xss"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	targetURL   string
	verbose     bool
	proxy       string
	timeout     int
	userAgent   string
	outputFile  string
	threads     int

	// Brute force flags
	userFile    string
	passFile    string
	userField   string
	passField   string
	successStr  string
	failStr     string
	bruteType   string
	rateLimit   float64

	// Shell flags
	execCommand  string
	shellType   string
	shellPassword string
	shellName   string
	shellIndex  int
	shellLocal  string
	shellRemote string
	genShell    bool
	genOutput   string

	// Stress test flags
	stressMethod      string
	stressBody        string
	stressHeaders     []string
	stressContentType string
	stressDuration    string
	stressRequests    int64
	stressRate        float64
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "webattack",
		Short: "Web Attack Security Testing Toolkit",
		Long: `Web Attack Toolkit - A comprehensive security testing tool for web applications.
		
This tool is intended for authorized security testing and educational purposes only.
Always obtain proper authorization before testing any system.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&targetURL, "url", "u", "", "Target URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "HTTP proxy (e.g., http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 15, "Request timeout in seconds")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent header")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file for results")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 5, "Number of concurrent threads")

	// SQLi command
	sqliCmd := &cobra.Command{
		Use:   "sqli",
		Short: "SQL Injection Scanner",
		Long:  `Detect SQL injection vulnerabilities in web application parameters.`,
		Run:   runSQLi,
	}
	sqliCmd.Flags().Bool("waf", false, "Detect WAF presence first")
	rootCmd.AddCommand(sqliCmd)

	// XSS command
	xssCmd := &cobra.Command{
		Use:   "xss",
		Short: "XSS Vulnerability Scanner",
		Long:  `Detect Cross-Site Scripting (XSS) vulnerabilities.`,
		Run:   runXSS,
	}
	rootCmd.AddCommand(xssCmd)

	// Scan command (full vulnerability scanner)
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Web Vulnerability Scanner",
		Long:  `Perform a comprehensive web vulnerability assessment.`,
		Run:   runScan,
	}
	rootCmd.AddCommand(scanCmd)

	// Brute force command
	bruteCmd := &cobra.Command{
		Use:   "brute",
		Short: "Brute Force Attack Tool",
		Long:  `Perform brute force attacks against web authentication.`,
		Run:   runBrute,
	}
	bruteCmd.Flags().StringVarP(&userFile, "users", "U", "", "File containing usernames (one per line)")
	bruteCmd.Flags().StringVarP(&passFile, "passwords", "P", "", "File containing passwords (one per line)")
	bruteCmd.Flags().StringVar(&userField, "user-field", "", "Username form field name")
	bruteCmd.Flags().StringVar(&passField, "pass-field", "", "Password form field name")
	bruteCmd.Flags().StringVar(&successStr, "success-str", "", "String indicating successful login")
	bruteCmd.Flags().StringVar(&failStr, "fail-str", "", "String indicating failed login")
	bruteCmd.Flags().StringVar(&bruteType, "type", "form", "Auth type: form, basic, digest")
	bruteCmd.Flags().Float64Var(&rateLimit, "rate", 10, "Requests per second")
	rootCmd.AddCommand(bruteCmd)

	// CSRF/SSRF command
	csrfssrfCmd := &cobra.Command{
		Use:   "csrf-ssrf",
		Short: "CSRF/SSRF Vulnerability Scanner",
		Long:  `Test for Cross-Site Request Forgery and Server-Side Request Forgery vulnerabilities.`,
		Run:   runCSRFSSRF,
	}
	csrfssrfCmd.Flags().String("callback", "", "Callback URL for OOB SSRF detection")
	rootCmd.AddCommand(csrfssrfCmd)

	// Shell command
	shellCmd := &cobra.Command{
		Use:   "shell",
		Short: "Web Shell Manager",
		Long:  `Manage and interact with web shells.`,
	}

	// Shell subcommands
	shellListCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered shells",
		Run:   runShellList,
	}
	shellCmd.AddCommand(shellListCmd)

	shellAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new shell",
		Run:   runShellAdd,
	}
	shellAddCmd.Flags().StringVar(&shellName, "name", "", "Shell name/alias")
	shellAddCmd.Flags().StringVar(&shellType, "type", "php", "Shell type: php, asp, aspx, jsp")
	shellAddCmd.Flags().StringVarP(&shellPassword, "password", "p", "cmd", "Shell password/parameter")
	shellCmd.AddCommand(shellAddCmd)

	shellExecCmd := &cobra.Command{
		Use:   "exec",
		Short: "Execute command on a shell",
		Run:   runShellExec,
	}
	shellExecCmd.Flags().IntVarP(&shellIndex, "id", "i", 0, "Shell index")
	shellExecCmd.Flags().StringVarP(&execCommand, "cmd", "c", "", "Command to execute")
	shellCmd.AddCommand(shellExecCmd)

	shellCheckCmd := &cobra.Command{
		Use:   "check",
		Short: "Check all shells",
		Run:   runShellCheck,
	}
	shellCmd.AddCommand(shellCheckCmd)

	shellRemoveCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a shell",
		Run:   runShellRemove,
	}
	shellRemoveCmd.Flags().IntVarP(&shellIndex, "id", "i", 0, "Shell index to remove")
	shellCmd.AddCommand(shellRemoveCmd)

	shellUploadCmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload file via shell",
		Run:   runShellUpload,
	}
	shellUploadCmd.Flags().IntVarP(&shellIndex, "id", "i", 0, "Shell index")
	shellUploadCmd.Flags().StringVarP(&shellLocal, "local", "l", "", "Local file path")
	shellUploadCmd.Flags().StringVarP(&shellRemote, "remote", "r", "", "Remote file path")
	shellCmd.AddCommand(shellUploadCmd)

	shellDownloadCmd := &cobra.Command{
		Use:   "download",
		Short: "Download file via shell",
		Run:   runShellDownload,
	}
	shellDownloadCmd.Flags().IntVarP(&shellIndex, "id", "i", 0, "Shell index")
	shellDownloadCmd.Flags().StringVarP(&shellRemote, "remote", "r", "", "Remote file path")
	shellDownloadCmd.Flags().StringVarP(&shellLocal, "local", "l", "", "Local save path")
	shellCmd.AddCommand(shellDownloadCmd)

	shellGenCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a web shell",
		Run:   runShellGenerate,
	}
	shellGenCmd.Flags().StringVar(&shellType, "type", "php", "Shell type: php, asp, aspx, jsp")
	shellGenCmd.Flags().StringVarP(&shellPassword, "password", "p", "cmd", "Shell password")
	shellGenCmd.Flags().StringVarP(&genOutput, "output", "o", "shell.php", "Output file")
	shellCmd.AddCommand(shellGenCmd)

	shellInteractiveCmd := &cobra.Command{
		Use:   "interact",
		Short: "Interactive shell session",
		Run:   runShellInteract,
	}
	shellInteractiveCmd.Flags().IntVarP(&shellIndex, "id", "i", 0, "Shell index")
	shellCmd.AddCommand(shellInteractiveCmd)

	rootCmd.AddCommand(shellCmd)

	// Stress test command
	stressCmd := &cobra.Command{
		Use:   "stress",
		Short: "Stress Test / Load Testing Tool",
		Long:  `Perform stress testing against web applications to evaluate performance and capacity.`,
		Run:   runStress,
	}
	stressCmd.Flags().StringVarP(&stressMethod, "method", "X", "GET", "HTTP method: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH")
	stressCmd.Flags().StringVarP(&stressBody, "body", "d", "", "Request body (for POST/PUT/PATCH)")
	stressCmd.Flags().StringArrayVarP(&stressHeaders, "header", "H", nil, "Custom header (e.g., 'Authorization: Bearer token')")
	stressCmd.Flags().StringVar(&stressContentType, "content-type", "", "Content-Type header")
	stressCmd.Flags().StringVarP(&stressDuration, "duration", "D", "10s", "Test duration (e.g., 10s, 1m, 5m)")
	stressCmd.Flags().Int64VarP(&stressRequests, "requests", "n", 0, "Total number of requests to send (overrides duration)")
	stressCmd.Flags().Float64VarP(&stressRate, "rate", "r", 0, "Requests per second rate limit (0 = unlimited)")
	rootCmd.AddCommand(stressCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// createClient creates an HTTP client from global flags
func createClient() *httpclient.Client {
	cfg := httpclient.DefaultConfig()

	if proxy != "" {
		cfg.Proxy = proxy
	}
	if timeout > 0 {
		cfg.Timeout = 0
		// Timeout is handled by cobra default
	}
	if userAgent != "" {
		cfg.UserAgent = userAgent
	}

	client, err := httpclient.NewClient(cfg)
	if err != nil {
		color.Red("Failed to create HTTP client: %v", err)
		os.Exit(1)
	}
	return client
}

func printBanner() {
	color.Cyan(`
██╗    ██╗███████╗██████╗  █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████║   ██║      ██║   ███████║██║     █████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
	`)
	fmt.Println("    Web Attack Security Testing Toolkit v1.0")
	fmt.Println("    For authorized security testing only.\n")
}

func runSQLi(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	client := createClient()

	// WAF detection
	detectWAF, _ := cmd.Flags().GetBool("waf")
	if detectWAF {
		fmt.Printf("[*] Detecting WAF...\n")
		waf := sqli.DetectWAF(client, targetURL)
		switch waf {
		case "none detected":
			color.Green("[+] No WAF detected")
		default:
			color.Yellow("[!] WAF detected: %s", waf)
		}
		fmt.Println()
	}

	scanner := sqli.NewScanner(client, verbose)
	results, err := scanner.Scan(targetURL)
	if err != nil {
		color.Red("Scan error: %v", err)
		os.Exit(1)
	}

	sqli.PrintResults(results)

	if outputFile != "" {
		report := sqli.GenerateReport(results, targetURL)
		os.WriteFile(outputFile, []byte(report), 0644)
		color.Green("\n[+] Report saved to: %s", outputFile)
	}
}

func runXSS(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	client := createClient()
	scanner := xss.NewScanner(client, verbose)
	results, err := scanner.Scan(targetURL)
	if err != nil {
		color.Red("Scan error: %v", err)
		os.Exit(1)
	}

	xss.PrintResults(results)
}

func runScan(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	client := createClient()
	webScan := scanner.NewScanner(client, verbose)
	results, err := webScan.Scan(targetURL)
	if err != nil {
		color.Red("Scan error: %v", err)
		os.Exit(1)
	}

	scanner.PrintResults(results)

	if outputFile != "" {
		report := scanner.Report(results, targetURL)
		os.WriteFile(outputFile, []byte(report), 0644)
		color.Green("\n[+] Report saved to: %s", outputFile)
	}
}

func runBrute(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	client := createClient()

	var usernames, passwords []string

	// Load wordlists
	if userFile != "" {
		data, err := os.ReadFile(userFile)
		if err != nil {
			color.Red("Failed to read user file: %v", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				usernames = append(usernames, line)
			}
		}
	}
	if passFile != "" {
		data, err := os.ReadFile(passFile)
		if err != nil {
			color.Red("Failed to read password file: %v", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				passwords = append(passwords, line)
			}
		}
	}

	// Use defaults if no files provided
	if len(usernames) == 0 {
		usernames = []string{"admin", "administrator", "root", "user"}
		fmt.Println("[*] Using default username list")
	}
	if len(passwords) == 0 {
		passwords = []string{"admin", "password", "123456", "admin123", "password123"}
		fmt.Println("[*] Using default password list")
	}

	var bType brute.TargetType
	switch bruteType {
	case "form":
		bType = brute.TargetForm
	case "basic":
		bType = brute.TargetBasic
	case "digest":
		bType = brute.TargetDigest
	default:
		color.Red("Unknown auth type: %s", bruteType)
		os.Exit(1)
	}

	b := brute.NewBruteForcer(client, targetURL, bType, verbose)
	b.SetThreads(threads)
	b.SetRateLimit(rateLimit)

	if userField != "" {
		b.SetFormFields(userField, passField)
	}
	if successStr != "" {
		b.SetSuccessIndicator(successStr)
	}
	if failStr != "" {
		b.SetFailIndicator(failStr)
	}

	results, err := b.Attack(usernames, passwords)
	if err != nil {
		color.Red("Attack error: %v", err)
		os.Exit(1)
	}

	brute.PrintResults(results)
}

func runCSRFSSRF(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	client := createClient()
	scanner := csrfssrf.NewScanner(client, verbose)

	callbackURL, _ := cmd.Flags().GetString("callback")
	if callbackURL != "" {
		scanner.SetCallbackURL(callbackURL)
	}

	results, err := scanner.Scan(targetURL)
	if err != nil {
		color.Red("Scan error: %v", err)
		os.Exit(1)
	}

	csrfssrf.PrintResults(results)
}

// Global shell manager instance
var shellMgr *shell.Manager

func getShellManager() *shell.Manager {
	if shellMgr == nil {
		shellMgr = shell.NewManager(createClient())
	}
	return shellMgr
}

func runShellList(cmd *cobra.Command, args []string) {
	mgr := getShellManager()
	shell.PrintShells(mgr.ListShells())
}

func runShellAdd(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" || shellName == "" {
		color.Red("Error: --url and --name are required")
		os.Exit(1)
	}

	mgr := getShellManager()
	mgr.AddShell(shellName, targetURL, shellType, shellPassword)
	color.Green("[+] Shell '%s' added successfully", shellName)
	shell.PrintShells(mgr.ListShells())
}

func runShellExec(cmd *cobra.Command, args []string) {
	if execCommand == "" {
		color.Red("Error: --cmd/-c is required")
		os.Exit(1)
	}

	mgr := getShellManager()
	output, err := mgr.ExecuteCommand(shellIndex, execCommand)
	if err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
	fmt.Println(output)
}

func runShellCheck(cmd *cobra.Command, args []string) {
	mgr := getShellManager()
	mgr.CheckAll()
}

func runShellRemove(cmd *cobra.Command, args []string) {
	mgr := getShellManager()
	if err := mgr.RemoveShell(shellIndex); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
	color.Green("[+] Shell %d removed", shellIndex)
}

func runShellUpload(cmd *cobra.Command, args []string) {
	if shellLocal == "" || shellRemote == "" {
		color.Red("Error: --local and --remote are required")
		os.Exit(1)
	}

	mgr := getShellManager()
	if err := mgr.UploadFile(shellIndex, shellLocal, shellRemote); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
	color.Green("[+] File uploaded successfully")
}

func runShellDownload(cmd *cobra.Command, args []string) {
	if shellRemote == "" || shellLocal == "" {
		color.Red("Error: --remote and --local are required")
		os.Exit(1)
	}

	mgr := getShellManager()
	if err := mgr.DownloadFile(shellIndex, shellRemote, shellLocal); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
	color.Green("[+] File downloaded to: %s", shellLocal)
}

func runShellGenerate(cmd *cobra.Command, args []string) {
	printBanner()

	if err := shell.SaveShellToFile(genOutput, shell.ShellType(shellType), shellPassword); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
	color.Green("[+] Shell generated: %s", genOutput)
	fmt.Printf("[*] Type: %s, Password: %s\n", shellType, shellPassword)
	fmt.Printf("[*] Upload to target and access: %s?%s=command\n", genOutput, shellPassword)
}

func runShellInteract(cmd *cobra.Command, args []string) {
	mgr := getShellManager()
	if err := shell.InteractiveShell(mgr, shellIndex); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}

func runStress(cmd *cobra.Command, args []string) {
	printBanner()

	if targetURL == "" {
		color.Red("Error: --url/-u is required")
		os.Exit(1)
	}

	// Parse duration - bare numbers are treated as seconds
	if stressDuration != "" {
		if _, err := time.ParseDuration(stressDuration); err != nil {
			// Try appending "s" for bare numbers like "120" -> "120s"
			stressDuration = stressDuration + "s"
		}
	}
	duration, err := time.ParseDuration(stressDuration)
	if err != nil {
		color.Red("Invalid duration format: %s (use e.g., 10s, 1m, 5m, or 120)", stressDuration)
		os.Exit(1)
	}

	// If --requests is set, ignore duration by setting to 0
	if stressRequests > 0 {
		duration = 0
	}

	// Parse custom headers
	headers := make(map[string]string)
	for _, h := range stressHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	client := createClient()

	cfg := stress.DefaultConfig()
	cfg.URL = targetURL
	cfg.Method = strings.ToUpper(stressMethod)
	cfg.Body = stressBody
	cfg.Headers = headers
	cfg.ContentType = stressContentType
	cfg.Workers = threads
	cfg.Duration = duration
	cfg.MaxRequests = stressRequests
	cfg.RateLimit = stressRate
	cfg.Verbose = verbose
	cfg.OutputFile = outputFile

	tester := stress.NewTester(client, cfg)
	stats, err := tester.Run()
	if err != nil {
		color.Red("Stress test error: %v", err)
		os.Exit(1)
	}

	stats.PrintReport()

	if outputFile != "" {
		report := stats.GenerateReport(targetURL)
		os.WriteFile(outputFile, []byte(report), 0644)
		color.Green("\n[+] Report saved to: %s", outputFile)
	}
}
