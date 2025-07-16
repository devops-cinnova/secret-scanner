import re
import math

__version__ = "1.2"

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"\b(A3T|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
    "AWS Secret Key": re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*([0-9a-zA-Z/+]{40})\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}\b"),
    "Stripe Secret Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
    "Stripe Restricted Key": re.compile(r"\brk_live_[0-9a-zA-Z]{24}\b"),
    "Stripe Test Key": re.compile(r"\bsk_test_[0-9a-zA-Z]{24}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_live_[0-9a-zA-Z]{24}\b"),
    "GitHub Token": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
    "GitHub Fine-Grained Token": re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{22,255}\b"),
    "GitLab Personal Access Token": re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20,}\b"),
    "Bitbucket App Password": re.compile(r"\bbba_[a-z0-9]{32}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
    "Google OAuth Access Token": re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b"),
    "Heroku API Key": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    "Discord Bot Token": re.compile(r"\b[M-N][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
    "Telegram Bot Token": re.compile(r"\b\d{9,10}:[A-Za-z0-9_-]{35}\b"),
    "Mailgun API Key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Twilio Auth Token": re.compile(r"(?i)\btwilio(?:_auth_token)?\b.*?[:=][ \t]*[a-f0-9]{32}\b"),
    "Facebook Access Token": re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b"),
    "Dropbox API Secret": re.compile(r"\bsl\.[A-Za-z0-9_-]{30,}\b"),
    "DigitalOcean Personal Access Token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "Datadog API Key": re.compile(r"\bddapi_[a-z0-9]{25}\b"),
    "Datadog Application Key": re.compile(r"\bddaak_[a-z0-9]{38}\b"),
    "Shopify Access Token": re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
    "Postman API Key": re.compile(r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b"),
    "Okta Token": re.compile(r"\b00[0-9a-zA-Z]{38}\$[0-9a-zA-Z]{20}\b"),
    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "MongoDB Atlas URI": re.compile(r"\bmongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[^\s]+"),
    "Azure SAS Token": re.compile(r"\bsv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%]{20,}\b"),
    "Atlassian API Token": re.compile(r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9]{24}\b"),
    "Sentry Auth Token": re.compile(r"\bsentry_auth_token_[0-9a-f]{32}\b"),
    "Vercel Token": re.compile(r"\bvercel\.token\.[a-zA-Z0-9_-]{84}\b")
}

ALLOWED_EXTENSIONS = (
    '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.tf', '.env', '.sh',
    '.php', '.java', '.log', '.txt', '.md', '.ini', '.cfg', '.toml', '.pem',
    '.crt', '.key', '.conf', '.csv', '.xml'
)

def shannon_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def is_probably_secret(token: str, min_entropy=3.5, min_length=20) -> bool:
    return token and len(token) >= min_length and shannon_entropy(token) >= min_entropy

def find_secrets_in_line(line: str):
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = pattern.findall(line)
        for match in matches:
            # Handle regexes that return group(1) or full match
            token = match if isinstance(match, str) else match[0]
            token = token.strip()
            if is_probably_secret(token):
                findings.append((secret_type, token))
    return findings
