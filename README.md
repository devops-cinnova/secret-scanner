# Secret-Scanner

Secret-Scanner is an advanced secrets detection tool designed for DevOps and security teams. It scans your codebase for a wide variety of sensitive information such as API keys, tokens, credentials, and private keys, helping you prevent accidental leaks before they reach production.

## Features
- Detects 50+ types of secrets, including AWS, GitHub, Google, Stripe, Slack, and more
- Scans a wide range of file types commonly found in code repositories
- Supports custom ignore patterns via `.secret-scanner-ignore` file
- Verbose mode for detailed scanning output
- Easy-to-read, colorized console output using [rich](https://github.com/Textualize/rich)

## Supported Secret Types (Examples)
- AWS Access Key & Secret Key
- Slack Token
- Stripe Secret Key
- GitHub Token & Fine-Grained Token
- Google API Key & OAuth Token
- Azure Keys & Tokens
- JWT Token
- Database Connection Strings
- Twilio Auth Token
- Generic API Keys
- Private Keys (RSA, DSA, EC, PGP, OpenSSH)
- Many more (see `scanner/utils.py` for the full list)

## Supported File Extensions
- `.py`, `.js`, `.ts`, `.json`, `.yaml`, `.yml`, `.tf`, `.env`, `.sh`, `.php`, `.java`, `.txt`, `.log`, `.md`, `.csv`, `.xml`, `.ini`, `.cfg`, `.conf`, `.toml`, `.bat`, `.ps1`, `.rb`, `.go`, `.c`, `.cpp`, `.h`, `.hpp`, `.pl`, `.swift`, `.scala`, `.kt`, `.dart`, `.rs`, `.cs`, `.vb`, `.asp`, `.aspx`, `.jsp`, `.html`, `.htm`, `.css`, `.scss`, `.less`, `.vue`, `.jsx`, `.tsx`, `.dockerfile`, `.properties`, `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, `.p12`, `.jks`, `.keystore`, `.b64`, `.bak`, `.backup`, `.old`, `.orig`, `.sample`, `.example`, `.template`, `.inc`, `.envrc`, `.secrets`, `.secret`, `.vault`, `.key`, `.token`, `.credentials`, `.passwd`, `.password`, `.pgpass`, `.mylogin.cnf`, `.npmrc`, `.yarnrc`, `.pypirc`, `.netrc`, `.dockerignore`, `.gitignore`, `.gitattributes`, `.editorconfig`, `.npmignore`, `.yarnignore`

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd secret_scanner
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To scan a directory (e.g., the provided `test/` folder):

```bash
python3 -m scanner.main --path test/
```

### Optional Arguments
- `--path <dir>`: Path to the directory or repository you want to scan (default: current directory)
- `--verbose`: Show detailed scanning progress and skipped files

### Example (with verbose output)
```bash
python3 -m scanner.main --path test/ --verbose
```

## Custom Ignore Patterns
You can create a `.secret-scanner-ignore` file in your target directory to specify files or patterns to exclude from scanning. Patterns support simple wildcards and directory matching.

## Output
- Secrets are displayed in a colorized, easy-to-read format, including file name, line number, risk type, and a snippet of the detected secret.
- If no secrets are found, you'll see a success message.

## License
MIT

---

*For more details on supported secret types and patterns, see `scanner/utils.py`.* 