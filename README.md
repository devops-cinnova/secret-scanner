# 🔐 Secret-Scanner by Cinnova

**Secret-Scanner** is a powerful and extensible secrets detection tool developed by **Cinnova** for DevOps and security teams. It helps identify sensitive information—such as API keys, tokens, credentials, and private keys—in your codebase before it reaches production.

---

## 🚀 Features

- Detects **50+ types** of secrets including AWS, GitHub, Google, Stripe, Slack, and more  
- Scans a wide range of common file types in modern code repositories  
- Supports custom ignore rules via `.secret-scanner-ignore`  
- Verbose mode for detailed scanning insights  
- Colorized, human-friendly console output using [rich](https://github.com/Textualize/rich)  

---

## 🕵️‍♂️ Detected Secrets (Examples)

- AWS Access & Secret Keys  
- Slack Tokens  
- Stripe Secret Keys  
- GitHub Personal & Fine-Grained Tokens  
- Google API Keys & OAuth Tokens  
- Azure Keys & Access Tokens  
- JSON Web Tokens (JWT)  
- Database Connection Strings  
- Twilio Auth Tokens  
- Generic API Keys  
- Private Keys: RSA, DSA, EC, PGP, OpenSSH  
- _...and many more (see `scanner/utils.py`)_  

---

## 📄 Supported File Extensions

Includes but not limited to:

`.py`, `.js`, `.ts`, `.json`, `.yaml`, `.yml`, `.tf`, `.env`, `.sh`, `.php`, `.java`, `.txt`, `.log`, `.md`, `.csv`, `.xml`, `.ini`, `.cfg`, `.conf`, `.toml`, `.bat`, `.ps1`, `.rb`, `.go`, `.c`, `.cpp`, `.h`, `.hpp`, `.pl`, `.swift`, `.scala`, `.kt`, `.dart`, `.rs`, `.cs`, `.vb`, `.asp`, `.aspx`, `.jsp`, `.html`, `.htm`, `.css`, `.scss`, `.less`, `.vue`, `.jsx`, `.tsx`, `.dockerfile`, `.properties`, `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, `.p12`, `.jks`, `.keystore`, `.b64`, `.bak`, `.backup`, `.old`, `.orig`, `.sample`, `.example`, `.template`, `.inc`, `.envrc`, `.secrets`, `.secret`, `.vault`, `.key`, `.token`, `.credentials`, `.passwd`, `.password`, `.pgpass`, `.mylogin.cnf`, `.npmrc`, `.yarnrc`, `.pypirc`, `.netrc`, `.dockerignore`, `.gitignore`, `.gitattributes`, `.editorconfig`, `.npmignore`, `.yarnignore`

---

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/devops-cinnova/secret-scanner
   cd secret_scanner
   
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt

## 📦 Usage
To scan a directory (e.g. the provided test/ folder):
   ```bash
   python3 -m scanner.main --path test/

