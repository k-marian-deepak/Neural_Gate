RULES: dict[str, list[str]] = {
    "sqli": [
        r"(?i)(\bunion\b\s+\bselect\b)",
        r"(?i)(\bor\b\s+1=1)",
        r"(?i)(information_schema|sleep\s*\()",
    ],
    "xss": [
        r"(?i)<script[^>]*>",
        r"(?i)javascript:",
        r"(?i)onerror\s*=",
    ],
    "lfi": [
        r"\.\./\.\./",
        r"(?i)/etc/passwd",
    ],
    "rfi": [
        r"(?i)https?://.*(cmd|shell)",
    ],
    "command_injection": [
        r"(;|&&|\|\|)\s*(cat|bash|sh|curl|wget)",
    ],
    "xxe": [
        r"(?i)<!DOCTYPE\s+[^>]+\[",
        r"(?i)SYSTEM\s+\"file://",
    ],
    "ssrf": [
        r"(?i)(127\.0\.0\.1|169\.254\.169\.254|localhost)",
    ],
    "shellcode": [
        r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
    ],
    "reverse_shell": [
        r"(?i)(/bin/bash\s+-i|nc\s+-e\s+/bin/sh)",
    ],
}
