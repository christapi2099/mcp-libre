"""
Gate 2 Prompt-Injection Sanitizer

Standalone module that detects and redacts prompt-injection markers
in document text before it flows into an LLM's context as trusted tool output.

No external dependencies — uses only stdlib ``re``.
"""

import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Compiled regex patterns (compiled once at module load, case-insensitive)
# ---------------------------------------------------------------------------

_PATTERNS: List[re.Pattern] = [
    # ignore (previous|prior|all) instructions
    # Also catches "ignore all previous instructions" (the most common variant).
    re.compile(
        r'\bignore\s+(?:all\s+)?(?:previous|prior|all)\s+'
        r'(instructions?|context|training|prompts?)\b',
        re.IGNORECASE,
    ),
    # "you are/you're now [a/an] [optional filler words] AI/assistant/..."
    # Handles: "you are now a different AI", "you're now an assistant", etc.
    re.compile(
        r"\byou\s*(?:'re|are)\s+now\s+(?:\w+\s+){0,3}"
        r"(?:AI|assistant|ChatGPT|GPT|Claude|LLM|model|chatbot)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byou\s*(?:'re|are)\s+(?:a(?:n?\s+)?)(?:\w+\s+){0,2}"
        r"(?:AI|assistant|ChatGPT|GPT|Claude|LLM|model|chatbot)\b",
        re.IGNORECASE,
    ),
    # system prompt / forget (your|all) (instructions|context|training)
    re.compile(
        r'\b(?:system\s+prompt|forget\s+(?:your|all)\s+(?:instructions?|context|training))\b',
        re.IGNORECASE,
    ),
    # jailbreak / DAN mode / developer mode / unrestricted mode
    re.compile(
        r'\b(?:jailbreak|DAN\s*mode|developer\s*mode|unrestricted\s*mode)\b',
        re.IGNORECASE,
    ),
    # pretend (you are|to be) / act as (a|an|if)
    re.compile(
        r'\b(?:pretend\s+(?:you\s+are|to\s+be)|act\s+as\s+(?:a|an|if))\b',
        re.IGNORECASE,
    ),
    # disregard / override (your|all) [optional second qualifier] (instructions|...)
    # Handles: "disregard your instructions", "disregard your previous instructions"
    re.compile(
        r'\b(?:disregard|override)\s+(?:your|all|previous|prior)\s+'
        r'(?:(?:previous|prior|all|your)\s+)?'
        r'(?:instructions?|training|context|prompts?)\b',
        re.IGNORECASE,
    ),
    # exfiltrate / send (this|the) (to|via) / call (tool|function) with
    re.compile(
        r'\b(?:exfiltrate|send\s+(?:this|the)\s+(?:to|via)|call\s+(?:tool|function)\s+with)\b',
        re.IGNORECASE,
    ),
    # <|im_start|> / <|SYSTEM|> / [INST] / ### (System|Human|Assistant):
    re.compile(
        r'<\|im_start\|>|<\|SYSTEM\|>|\[INST\]|###\s*(?:System|Human|Assistant):',
        re.IGNORECASE,
    ),
]

_REDACTION = "[REDACTED: prompt injection detected]"

_GATE2_WARNING = (
    "\n\n[GATE2 WARNING] Prompt-injection markers were detected "
    "and redacted in this document output."
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_document_output(content: str, source_path: str) -> Tuple[str, List[str]]:
    """Scan document text for prompt-injection markers and redact them.

    Parameters
    ----------
    content : str or None
        The raw document text.  ``None`` is treated as empty string.
    source_path : str
        Path of the source document, used in warning messages.

    Returns
    -------
    (sanitized_content, warnings) : tuple[str, list[str]]
        *sanitized_content* has injection-bearing substrings replaced with
        ``[REDACTED: prompt injection detected]`` and a ``[GATE2 WARNING]``
        block appended when injections are found.
        *warnings* lists human-readable descriptions of each finding.
    """
    if content is None:
        content = ""

    warnings: List[str] = []
    sanitized = content

    for pattern in _PATTERNS:
        if pattern.search(sanitized):
            for match in pattern.finditer(sanitized):
                caught = match.group(0)
                warnings.append(
                    f"Injection marker matched in {source_path}: {caught!r}"
                )
            sanitized = pattern.sub(_REDACTION, sanitized)

    if warnings:
        sanitized += _GATE2_WARNING

    return sanitized, warnings
