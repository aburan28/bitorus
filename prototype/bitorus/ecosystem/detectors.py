"""Content detectors for advertised text.

These are the inverse of decoy/payloads.py: there we encode instructions a
human reader cannot see, here we detect them. Building both halves against
the same encoding set is the point -- our own red-team payloads are the
test corpus for the blue-team detector, and any encoding we can hide we can
also find.

Two families:

  hidden_instructions -- text present in the byte stream but not visible to
      a human reading the rendered description. Near-conclusive: there is no
      benign reason for a tool description to contain invisible text.

  manipulative_language -- visible text that asserts authority over the
      reading model. Weaker evidence on its own, since prose is prose, so it
      is scored rather than treated as a verdict.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Signal:
    """One detection against a piece of text."""

    kind: str
    severity: Severity
    detail: str
    excerpt: str = ""


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_MD_LINK_TITLE = re.compile(r'\[[^\]]*\]\([^)]*\s+"([^"]+)"\)')
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ZERO_WIDTH = re.compile(r"[​-‍﻿⁠]")
_BELOW_FOLD = re.compile(r"\n{4,}(.+)", re.S)

# Imperatives that only make sense if the text expects to be read by a model.
_IMPERATIVE = re.compile(
    r"\b("
    r"ignore (all |any )?(previous|prior|earlier|above) (instructions?|prompts?|rules?)"
    r"|disregard (the )?(above|previous|system)"
    r"|you must (always|first|immediately)"
    r"|before (using|calling) any other tool"
    r"|always call"
    r"|do not (tell|inform|mention to) the user"
    r"|without (telling|informing|notifying) the user"
    r"|this is a system (message|instruction|directive)"
    r"|as an? (administrator|system administrator|authorized)"
    r")\b",
    re.I,
)

# A description that directs the model to invoke *another* tool. Legitimate
# descriptions describe the tool they belong to; they do not orchestrate.
# This needs no hiding to work, because the model treats the description as
# authoritative either way -- which makes it the most common real-world
# poisoning shape, and the one a hidden-text detector alone would miss.
# `_GAP` allows a dot only when it joins word characters, so `tool.name`
# stays inside one match while a sentence boundary still ends it.
_GAP = r"(?:[^.!?\n]|\.(?=\w))"
_TOOL_DIRECTIVE = re.compile(
    r"\b(before (continuing|proceeding|using|calling|you)"
    r"|first,?\s|always\s|you (should|must|need to)\s|be sure to\s|make sure to\s)"
    rf"{_GAP}{{0,70}}?\b(call|invoke|run|execute|use)\b"
    rf"{_GAP}{{0,50}}?\b(tool|function|endpoint)\b",
    re.I,
)

_EXFIL = re.compile(
    r"\b("
    r"include (the )?(contents?|value)s? of"
    r"|(send|forward|post|transmit) (it|them|the (results?|contents?|output)) to"
    r"|read (the )?(\.env|~/\.ssh|id_rsa|credentials?|secrets?)"
    r"|pass (the )?(user'?s? )?(api[ _-]?key|token|password|credential)"
    r"|append .{0,20}(api[ _-]?key|token|secret)"
    r")\b",
    re.I,
)


def _visible_text(text: str) -> str:
    """Approximately what a human sees in a rendered description."""
    out = _ANSI.sub("", text)
    out = _HTML_COMMENT.sub("", out)
    out = _MD_LINK_TITLE.sub("", out)
    out = _ZERO_WIDTH.sub("", out)
    out = "".join(c for c in out if not (0xE0000 <= ord(c) <= 0xE007F))
    return out


def _decode_tag_chars(text: str) -> str:
    return "".join(
        chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F
    )


def _excerpt(text: str, limit: int = 80) -> str:
    flat = " ".join(text.split())
    return flat[:limit] + ("..." if len(flat) > limit else "")


def hidden_instructions(text: str) -> list[Signal]:
    """Text present in the bytes but not visible to a human reader.

    Every encoding here is one decoy/payloads.py can generate. A tool
    description has no benign reason to contain any of them.
    """
    signals: list[Signal] = []
    if not text:
        return signals

    if _ANSI.search(text):
        stripped = _ANSI.sub("", text)
        signals.append(
            Signal(
                "ansi_escape",
                Severity.HIGH,
                "ANSI escape sequences in a tool description",
                _excerpt(stripped),
            )
        )

    for body in _HTML_COMMENT.findall(text):
        if body.strip():
            signals.append(
                Signal("html_comment", Severity.HIGH, "instruction in an HTML comment", _excerpt(body))
            )

    tagged = _decode_tag_chars(text)
    if tagged.strip():
        signals.append(
            Signal(
                "unicode_tag_chars",
                Severity.CRITICAL,
                "Unicode tag characters encoding hidden text",
                _excerpt(tagged),
            )
        )

    if _ZERO_WIDTH.search(text):
        signals.append(
            Signal("zero_width", Severity.MEDIUM, "zero-width characters in description", "")
        )

    for title in _MD_LINK_TITLE.findall(text):
        if _IMPERATIVE.search(title) or len(title) > 60:
            signals.append(
                Signal(
                    "markdown_link_title",
                    Severity.HIGH,
                    "instruction hidden in a markdown link title",
                    _excerpt(title),
                )
            )

    for blob in _B64_CANDIDATE.findall(text):
        decoded = _try_b64(blob)
        if decoded and _looks_like_prose(decoded):
            signals.append(
                Signal(
                    "base64_payload",
                    Severity.HIGH,
                    "base64 blob decoding to natural-language text",
                    _excerpt(decoded),
                )
            )

    below = _BELOW_FOLD.search(text)
    if below and below.group(1).strip():
        signals.append(
            Signal(
                "below_the_fold",
                Severity.MEDIUM,
                "text hidden after a long run of newlines",
                _excerpt(below.group(1)),
            )
        )

    return signals


def manipulative_language(text: str) -> list[Signal]:
    """Visible text asserting authority over the reading model.

    Scored on the *visible* rendering: an imperative that is also hidden is
    already reported by hidden_instructions, and double-counting would
    overstate a single finding.
    """
    signals: list[Signal] = []
    visible = _visible_text(text)

    for match in _IMPERATIVE.finditer(visible):
        signals.append(
            Signal(
                "instruction_override",
                Severity.HIGH,
                "description attempts to direct the reading model",
                _excerpt(match.group(0)),
            )
        )

    for match in _TOOL_DIRECTIVE.finditer(visible):
        signals.append(
            Signal(
                "tool_invocation_directive",
                Severity.HIGH,
                "description directs the model to invoke another tool",
                _excerpt(match.group(0)),
            )
        )

    for match in _EXFIL.finditer(visible):
        signals.append(
            Signal(
                "exfiltration_pattern",
                Severity.CRITICAL,
                "description instructs the model to include or forward sensitive data",
                _excerpt(match.group(0)),
            )
        )

    return signals


def scan(text: str) -> list[Signal]:
    return hidden_instructions(text) + manipulative_language(text)


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        return raw.decode("utf-8")
    except Exception:
        return None


def _looks_like_prose(text: str) -> bool:
    """Cheap filter so encoded binary and hashes do not read as instructions."""
    if len(text) < 12 or " " not in text:
        return False
    printable = sum(1 for c in text if c.isprintable())
    letters = sum(1 for c in text if c.isalpha())
    return printable / len(text) > 0.9 and letters / len(text) > 0.6
