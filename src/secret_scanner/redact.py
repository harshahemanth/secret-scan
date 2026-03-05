# src/secret_scanner/redact.py

"""Redact secret values in scan output to prevent credential leaks."""


def redact_match(text: str) -> str:
    """Redact a matched secret value.

    - len <= 8:   "****"
    - len 9-11:   first 2 + "****" + last 2
    - len >= 12:  first 4 + "****" + last 4
    """
    length = len(text)
    if length <= 8:
        return "****"
    elif length <= 11:
        return text[:2] + "****" + text[-2:]
    else:
        return text[:4] + "****" + text[-4:]


def redact_matches(matches: list) -> list:
    """Return a new list of match dicts with the 'match' field redacted."""
    redacted = []
    for m in matches:
        copy = dict(m)
        if "match" in copy:
            copy["match"] = redact_match(copy["match"])
        redacted.append(copy)
    return redacted
