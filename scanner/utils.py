import re
__version__ = "1.1"

SECRET_PATTERNS = {    
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key[^a-zA-Z0-9]*[0-9a-zA-Z\/+]{40}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Azure Key": r"(?i)azure.*(?:key|token)[\s:=]+[a-z0-9]{32,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",
    "DB Connection String": r"(?i)(postgres|mysql|mongodb):\/\/.+:[^@]+@[^:\/]+",
    "Basic Auth URL": r"https?:\/\/[^\/\s]+:[^\/\s]+@[^\/\s]+",
    "Twilio Auth Token": r"(?i)twilio.*(?:token|auth)[\s:=]+[a-f0-9]{32}",
    "Generic API Key": r"(?i)(?:api|apikey|token|secret)[^a-zA-Z0-9]*[0-9a-zA-Z]{16,}",
    "AWS Session Token": r"(?i)aws_session_token[^a-zA-Z0-9]*[A-Za-z0-9/+=]{16,}",
    "Azure Storage Account Key": r"[A-Za-z0-9+/=]{88}",
    "Azure SAS Token": r"sv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%]+",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Google Cloud Service Account": r'"type": "service_account"',
    "GitHub Fine-Grained Token": r"github_pat_[0-9a-zA-Z_]{22,255}",
    "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-_]{20,}",
    "GitLab Runner Registration Token": r"GR1348941[a-zA-Z0-9_-]{20,}",
    "Bitbucket App Password": r"bba_[a-z0-9]{32}",
    "Atlassian API Token": r"[A-Za-z0-9]{24}\.[A-Za-z0-9]{24}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Telegram Bot Token": r"\d{9,10}:[A-Za-z0-9_-]{35}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Datadog API Key": r"ddapi_[a-z0-9]{25}",
    "Datadog Application Key": r"ddaak_[a-z0-9]{38}",
    "DigitalOcean Personal Access Token": r"dop_v1_[a-f0-9]{64}",
    "MongoDB Atlas Service Account Key": r"mongodb(\+srv)?:\/\/[\w\-]+:[^@]+@[^:]+(:\d+)?\/\w+",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "Bearer Token": r"Bearer [A-Za-z0-9\-\._~\+\/]+=*",
    "Google Cloud API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Firebase Cloud Messaging Server Key": r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140,}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22,43}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",
    "Twilio API Secret": r"[a-f0-9]{32}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Algolia Admin API Key": r"[a-f0-9]{32}",
    "Cloudinary API Key": r"[0-9]{15,20}-[0-9a-zA-Z]{10,20}",
    "Postman API Key": r"PMAK-[0-9a-f]{24}\-[0-9a-f]{34}",
    "Okta Token": r"00[0-9a-zA-Z]{38}\$[0-9a-zA-Z]{20}",
    "Auth0 Client Secret": r"[a-zA-Z0-9]{64}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
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
