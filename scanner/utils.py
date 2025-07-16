import re
__version__ = "1.1"

SECRET_PATTERNS = {
    "AWS Access Key": r"\b(A3T|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
    "AWS Secret Key": r"(?i)\baws_secret_access_key\s*[:=]\s*([0-9a-zA-Z/+]{40})\b",
    "Slack Token": r"\bxox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}\b",
    "Stripe Secret Key": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "Stripe Restricted Key": r"\brk_live_[0-9a-zA-Z]{24}\b",
    "Stripe Test Key": r"\bsk_test_[0-9a-zA-Z]{24}\b",
    "Stripe Publishable Key": r"\bpk_live_[0-9a-zA-Z]{24}\b",
    "GitHub Token": r"\bghp_[0-9a-zA-Z]{36}\b",
    "GitHub Fine-Grained Token": r"\bgithub_pat_[0-9a-zA-Z_]{22,255}\b",
    "GitLab Personal Access Token": r"\bglpat-[0-9a-zA-Z\-_]{20,}\b",
    "Bitbucket App Password": r"\bbba_[a-z0-9]{32}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z-_]{35}\b",
    "Google OAuth Access Token": r"\bya29\.[0-9A-Za-z\-_]+\b",
    "Heroku API Key": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "Discord Bot Token": r"\b[M-N][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b",
    "Telegram Bot Token": r"\b\d{9,10}:[A-Za-z0-9_-]{35}\b",
    "Mailgun API Key": r"\bkey-[0-9a-zA-Z]{32}\b",
    "SendGrid API Key": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "Twilio Auth Token": r"(?i)\btwilio(?:_auth_token)?\b.*?[:=][ \t]*[a-f0-9]{32}\b",
    "Facebook Access Token": r"\bEAACEdEose0cBA[0-9A-Za-z]+\b",
    "Dropbox API Secret": r"\bsl\.[A-Za-z0-9_-]{30,}\b",
    "DigitalOcean Personal Access Token": r"\bdop_v1_[a-f0-9]{64}\b",
    "Datadog API Key": r"\bddapi_[a-z0-9]{25}\b",
    "Datadog Application Key": r"\bddaak_[a-z0-9]{38}\b",
    "Shopify Access Token": r"\bshpat_[a-fA-F0-9]{32}\b",
    "Postman API Key": r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b",
    "Okta Token": r"\b00[0-9a-zA-Z]{38}\$[0-9a-zA-Z]{20}\b",
    "JWT Token": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "MongoDB Atlas URI": r"\bmongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[^\s]+",
    "Azure SAS Token": r"\bsv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%]{20,}\b",
    "Atlassian API Token": r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9]{24}\b",
    "Sentry Auth Token": r"\bsentry_auth_token_[0-9a-f]{32}\b",
    "Vercel Token": r"\bvercel\.token\.[a-zA-Z0-9_-]{84}\b"
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
