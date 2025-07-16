import re
__version__ = "1.1"

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key.{0,20}([0-9a-zA-Z/+]{40})",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Fine-Grained Token": r"github_pat_[0-9a-zA-Z_]{22,255}",
    "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-_]{20,}",
    "Bitbucket App Password": r"bba_[a-z0-9]{32}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Telegram Bot Token": r"\d{9,10}:[A-Za-z0-9_-]{35}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"(?i)twilio.*(?:token|auth)[\s:=]+[a-f0-9]{32}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Dropbox API Secret": r"sl\.[A-Za-z0-9_-]{15,}",
    "DigitalOcean Personal Access Token": r"dop_v1_[a-f0-9]{64}",
    "Datadog API Key": r"ddapi_[a-z0-9]{25}",
    "Datadog Application Key": r"ddaak_[a-z0-9]{38}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Postman API Key": r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
    "Okta Token": r"00[0-9a-zA-Z]{38}\$[0-9a-zA-Z]{20}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\\s\\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "MongoDB Atlas Service Account Key": r"mongodb(\+srv)?:\/\/[\w\-]+:[^@]+@[^:]+(:\d+)?\/\w+",
    "Azure Storage Account Key": r"[A-Za-z0-9+/=]{88}",
    "Azure SAS Token": r"sv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%]+",
    "Atlassian API Token": r"[A-Za-z0-9]{24}\.[A-Za-z0-9]{24}",
    "Sentry Auth Token": r"sentry_auth_token_[0-9a-f]{32}",
    "Vercel Token": r"vercel\.token\.[a-zA-Z0-9_-]{84}",
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
