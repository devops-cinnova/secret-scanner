import re
__version__ = "1.1"

SECRET_PATTERNS = {
    # === Cloud Providers ===
    "AWS Access Key": r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])", 
    "AWS Secret Key": r"(?i)aws_secret_access_key[^a-z0-9]{0,5}[:=][^a-z0-9/+]{0,5}[0-9a-zA-Z/+]{40}",
    "AWS Session Token": r"(?i)aws_session_token[^a-z0-9]{0,5}[:=][^a-z0-9/+]{0,5}[A-Za-z0-9/+=]{16,}",
    "GCP API Key": r"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])",
    "GCP OAuth Token": r"(?<![A-Za-z0-9])ya29\.[0-9A-Za-z\-_]+(?![A-Za-z0-9])",
    "GCP Service Account": r'"type"\s*:\s*"service_account"',
    "Azure Access Token": r"(?i)azure[^a-z0-9]{0,5}(access_)?(key|token)[^a-z0-9]{0,5}[:=][^a-z0-9]{0,5}[a-z0-9]{32,}",
    "Azure Storage Key": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{88}(?![A-Za-z0-9+/=])",
    "Azure SAS Token": r"sv=\d{4}-\d{2}-\d{2}.*?&sig=[A-Za-z0-9%]+",
    # === Git & CI/CD ===
    "GitHub Token": r"gh[pusr]_[0-9a-zA-Z]{36}",
    "GitHub App Token": r"ghu_[0-9a-zA-Z]{36}",
    "GitHub Actions Token": r"ghs_[0-9a-zA-Z]{36}",
    "GitHub Fine-Grained Token": r"github_pat_[0-9a-zA-Z_]{22,255}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20,}",
    "GitLab Deploy Token": r"gldt-[0-9a-zA-Z\-_]{20,}",
    "Bitbucket App Password": r"bba_[a-z0-9]{32}",
    "CircleCI Token": r"circleci_token[^a-z0-9:=]{0,5}[:=][^a-z0-9]{0,5}[a-zA-Z0-9_\-]{40}",
    "Terraform Cloud Token": r"tfr_[a-zA-Z0-9]{32,64}",
    # === Auth & OAuth ===
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",
    "Bearer Token": r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
    "Okta Token": r"00[0-9a-zA-Z]{38}\$[0-9a-zA-Z]{20}",
    "Auth0 Client Secret": r"(?i)client_secret[^a-z0-9:=]{0,5}[:=][^a-z0-9]{0,5}[a-zA-Z0-9\-_]{32,}",
    # === SaaS APIs ===
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio SID": r"AC[a-f0-9]{32}",
    "Twilio Token": r"SK[a-f0-9]{32}",
    "Twilio Auth Token": r"(?i)twilio[^a-z0-9]{0,5}(token|auth)[^:=]{0,5}[:=][^a-z0-9]{0,5}[a-f0-9]{32}",
    "Shopify Token": r"shpat_[a-fA-F0-9]{32}",
    "Notion Token": r"secret_[a-zA-Z0-9]{43}",
    "Postman API Key": r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
    "Datadog API Key": r"ddapi_[a-z0-9]{25}",
    "Datadog App Key": r"ddaak_[a-z0-9]{38}",
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    # === Credentials & Secrets ===
    "Hardcoded Password":r"(?i)(password|passwd|pwd)[^a-zA-Z0-9]{0,10}[:=]\s*['\"]?[^\s\"']{6,}['\"]?",
    "Hardcoded Secret": r"(?i)(secret|secrettoken)[^a-z0-9]{0,10}[:=][^a-z0-9\"']{0,10}[^\s\"']{6,}",
    "Hardcoded API Key": r"(?i)(api[_\-]?key)[^a-z0-9]{0,10}[:=][^a-z0-9\"']{0,10}[a-z0-9\-_]{16,}",
    # === URLs & URIs ===
    "Basic Auth in URL": r"https?:\/\/[^\/:\s]+:[^@\/\s]+@[^\/\s]+",
    "PostgreSQL URI": r"postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^:\s]+(?::\d+)?\/[^?\s]+",
    "MySQL URI": r"mysql:\/\/[^:\s]+:[^@\s]+@[^:\s]+(?::\d+)?\/[^?\s]+",
    "MongoDB URI": r"mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^:\s\/]+(?:[:\d]+)?\/[^\s]+",
    # === Encoded Secrets ===
    "Base64 PEM Block": r"(LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLS[\w+/=]{100,})",
    "Hexadecimal Key": r"\b[a-f0-9]{32,64}\b",
    "Base64 String": r"\b(?:[A-Za-z0-9+/]{30,}={0,2}){2,}\b",
    # === Private Keys ===
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    # === Shell Exports ===
    "Shell Exported Secret": r"(?i)export\s+([A-Z_]*SECRET[^=\s]*)=['\"]?[^\s'\"]{10,}",
}


ALLOWED_EXTENSIONS = (
    '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.tf', '.env', '.sh', '.php', '.java', '.txt', '.log', '.md', '.csv', '.xml', '.ini', '.cfg', '.conf', '.toml', '.bat', '.ps1', '.rb', '.go', '.c', '.cpp', '.h', '.hpp', '.pl', '.swift', '.scala', '.kt', '.dart', '.rs', '.cs', '.vb', '.asp', '.aspx', '.jsp', '.html', '.htm', '.css', '.scss', '.less', '.vue', '.jsx', '.tsx', '.dockerfile', '.properties', '.pem', '.crt', '.cer', '.der', '.pfx', '.p12', '.jks', '.keystore', '.b64', '.bak', '.backup', '.old', '.orig', '.sample', '.example', '.template', '.inc', '.envrc', '.secrets', '.secret', '.vault', '.key', '.token', '.credentials', '.passwd', '.password', '.pgpass', '.mylogin.cnf', '.npmrc', '.yarnrc', '.pypirc', '.netrc', '.dockerignore', '.gitignore', '.gitattributes', '.editorconfig', '.npmignore', '.yarnignore'
)

def find_secrets_in_line(line):
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, line)
        for match in matches:
            findings.append((secret_type, match))
    return findings
