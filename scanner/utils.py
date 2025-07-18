import re
import math
import os

__version__ = "2.0"
SECRET_PATTERNS = {
    "AWS Access Key": {
        "regex": re.compile(r"(?<![A-Z0-9])(A3T|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}(?![A-Z0-9])"),
        "min_entropy": 3.5,
        "min_length": 20,
        "confidence": 0.9,
    },
    "AWS Secret Key": {
        "regex": re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*([0-9a-zA-Z/+]{40})\b"),
        "min_entropy": 4.0,
        "min_length": 40,
        "confidence": 0.95,
    },
    "GitHub Token": {
        "regex": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
        "min_entropy": 4.2,
        "min_length": 36,
        "confidence": 0.95,
    },
    "Slack Token": {
        "regex": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}\b"),
        "min_entropy": 4.0,
        "min_length": 60,
        "confidence": 0.95,
    },
    "Stripe Secret Key": {
        "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
        "min_entropy": 3.8,
        "min_length": 32,
        "confidence": 0.9,
    },
    "Google API Key": {
        "regex": re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
        "min_entropy": 4.0,
        "min_length": 39,
        "confidence": 0.9,
    },
    "Private Key": {
        "regex": re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ED25519) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP|ED25519) PRIVATE KEY-----"
        ),
        "min_entropy": 3.0,
        "min_length": 50,
        "confidence": 1.0,
    },
    "JWT Token": {
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
        "min_entropy": 3.5,
        "min_length": 30,
        "confidence": 0.8,
    },
    "Base64 Encoded Secret": {
        "regex": re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"),
        "min_entropy": 4.2,
        "min_length": 40,
        "confidence": 0.6,
    },
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

def is_allowed_file(filename: str) -> bool:
    return filename.lower().endswith(ALLOWED_EXTENSIONS)

def find_secrets_in_line(line: str, line_num: int = 0):
    findings = []
    for secret_type, config in SECRET_PATTERNS.items():
        pattern = config["regex"]
        min_entropy = config.get("min_entropy", 3.5)
        min_length = config.get("min_length", 20)
        confidence = config.get("confidence", 0.5)

        matches = pattern.findall(line)
        for match in matches:
            token = match if isinstance(match, str) else match[0]
            token = token.strip()
            if is_probably_secret(token, min_entropy, min_length):
                findings.append({
                    "type": secret_type,
                    "value": token,
                    "confidence": confidence,
                    "line": line_num,
                    "text": line.strip()
                })
    return findings

