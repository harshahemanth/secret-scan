# src/secret_scanner/patterns.py

import re

PATTERN_SOURCE = r"""
(
    # Existing patterns ...

    (?:mongodb|postgres|mysql|jdbc|redis|ftp|smtp)[\s_\-=:][A-Za-z0-9+=._-]{10,}|
    Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|
    ClientSecret"\svalue=.+|
    (?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|
    AccountKey=\S{10,}|
    secret_key_base:\s.[A-Za-z0-9_.-]{12,}|
    secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}|
    Bearer\s.\S{11,}|
    api[_-](?:key|token)(?::|=).[A-Za-z0-9_.-]{10,}|
    ssh-rsa\s+[A-Za-z0-9+/=]+|
    -----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|
    (?:password|passwd|pwd|Password|PASSWORD)\s*[:=]\s*["']?[^\s"']{8,}|
    eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|


    # AWS access key IDs (AKIA..., etc.)
    (?:AWS|aws)_?(?:ACCESS_KEY_ID|ACCESS_KEY|ACCESSKEY)\s*[:=]\s*["']?(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}["']?|
    (?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}|   # standalone


    # AWS secret access keys
    (?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?|
    aws_?(?:secret|access)?_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{16,}["']?|


    # OpenAI API keys (sk-)
    (?:OPENAI_API_KEY|openai_api_key)\s*[:=]\s*["']?sk-[A-Za-z0-9]{20,}["']?|
    sk-[A-Za-z0-9]{20,}
)
"""


def build_pattern() -> re.Pattern:
    return re.compile(PATTERN_SOURCE, re.IGNORECASE | re.VERBOSE)

