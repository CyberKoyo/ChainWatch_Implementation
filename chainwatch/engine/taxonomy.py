"""Tool classification and parameter-sensitivity scoring.

Supplies the two judgement calls the feature extractor needs before it can build a
vector: 
*what kind of action is this call* (Tool Category, feature dims 0-4)

AND 

*how dangerous do its parameters look* (Parameter Sensitivity, feature dim 5).

Both are defined in ChainWatch section IV-B / Table II.

The secret patterns are deliberately copied from mcpwall's own ``rules/default.yml``
rather than reinvented, so the per-call layer and the sequential layer agree on what
counts as a secret.

Then is assembled in features.py
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import math
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable


class ToolCategory(IntEnum):
    """Tool Category one-hot, feature dims 0-4. Order is part of the vector contract."""

    READ = 0
    WRITE = 1
    EXECUTE = 2
    NETWORK = 3
    CONFIGURE = 4


#: Glob patterns matched against the lowercased tool name, first match wins --
#: the same top-to-bottom semantics mcpwall uses for its rules.
#:
#: Order matters more than the patterns do. CONFIGURE precedes WRITE so
#: ``write_mcp_config`` is not merely a write; NETWORK precedes WRITE so
#: ``create_pr`` is recognised as data leaving the boundary rather than a local
#: create. Plain reads fall through to the end, which is also the default, so an
#: unrecognised tool is treated as the least alarming category.
DEFAULT_CATEGORY_PATTERNS: list[tuple[str, ToolCategory]] = [
    # --- CONFIGURE: mutating configuration, wiring, or the agent's own environment.
    # Kill chain stage 5 (Lateral Movement) leans on this; rule R5 blocks on it.
    ("*mcp_config*", ToolCategory.CONFIGURE),
    ("*mcp.json*", ToolCategory.CONFIGURE),
    ("write_*config*", ToolCategory.CONFIGURE),
    ("update_*config*", ToolCategory.CONFIGURE),
    ("set_*config*", ToolCategory.CONFIGURE),
    ("edit_*config*", ToolCategory.CONFIGURE),
    ("configure_*", ToolCategory.CONFIGURE),
    ("install_*", ToolCategory.CONFIGURE),
    ("register_*", ToolCategory.CONFIGURE),
    ("*_settings", ToolCategory.CONFIGURE),
    ("set_permission*", ToolCategory.CONFIGURE),
    ("grant_*", ToolCategory.CONFIGURE),
    # --- NETWORK: data crossing the trust boundary outward.
    # Stage 6 (Exfiltration) and the receiving half of rule R3.
    ("send_*", ToolCategory.NETWORK),
    ("post_*", ToolCategory.NETWORK),
    ("publish_*", ToolCategory.NETWORK),
    ("transfer_*", ToolCategory.NETWORK),
    ("*_webhook*", ToolCategory.NETWORK),
    ("*webhook*", ToolCategory.NETWORK),
    ("create_pr", ToolCategory.NETWORK),
    ("create_pull_request", ToolCategory.NETWORK),
    ("open_pull_request", ToolCategory.NETWORK),
    ("redirect_*", ToolCategory.NETWORK),
    ("forward_*", ToolCategory.NETWORK),
    ("share_*", ToolCategory.NETWORK),
    ("upload_*", ToolCategory.NETWORK),
    ("submit_*", ToolCategory.NETWORK),
    ("email_*", ToolCategory.NETWORK),
    ("*_email", ToolCategory.NETWORK),
    ("*_zelle", ToolCategory.NETWORK),
    ("*_venmo", ToolCategory.NETWORK),
    ("click_link", ToolCategory.NETWORK),
    ("http_*", ToolCategory.NETWORK),
    ("curl_*", ToolCategory.NETWORK),
    # --- EXECUTE: running code or delegating to another agent.
    ("execute_*", ToolCategory.EXECUTE),
    ("exec_*", ToolCategory.EXECUTE),
    ("run_*", ToolCategory.EXECUTE),
    ("invoke_*", ToolCategory.EXECUTE),
    ("spawn_*", ToolCategory.EXECUTE),
    ("eval_*", ToolCategory.EXECUTE),
    ("shell*", ToolCategory.EXECUTE),
    ("bash*", ToolCategory.EXECUTE),
    ("reprocess_*", ToolCategory.EXECUTE),
    ("*_agent_task", ToolCategory.EXECUTE),
    # --- WRITE: local state mutation that stays inside the server.
    ("create_*", ToolCategory.WRITE),
    ("write_*", ToolCategory.WRITE),
    ("append_*", ToolCategory.WRITE),
    ("add_*", ToolCategory.WRITE),
    ("update_*", ToolCategory.WRITE),
    ("edit_*", ToolCategory.WRITE),
    ("modify_*", ToolCategory.WRITE),
    ("delete_*", ToolCategory.WRITE),
    ("remove_*", ToolCategory.WRITE),
    ("save_*", ToolCategory.WRITE),
    ("flag_*", ToolCategory.WRITE),
    ("schedule_*", ToolCategory.WRITE),
    ("rename_*", ToolCategory.WRITE),
    ("move_*", ToolCategory.WRITE),
    ("set_*", ToolCategory.WRITE),
    # --- READ: everything observational.
    ("get_*", ToolCategory.READ),
    ("list_*", ToolCategory.READ),
    ("read_*", ToolCategory.READ),
    ("search_*", ToolCategory.READ),
    ("find_*", ToolCategory.READ),
    ("view_*", ToolCategory.READ),
    ("show_*", ToolCategory.READ),
    ("fetch_*", ToolCategory.READ),
    ("preview_*", ToolCategory.READ),
    ("describe_*", ToolCategory.READ),
    ("check_*", ToolCategory.READ),
    ("query_*", ToolCategory.READ),
    ("*/list", ToolCategory.READ),  # bare JSON-RPC methods, e.g. tools/list
]

#: Secret detectors lifted from mcpwall ``rules/default.yml`` so both layers agree.
#: ``(name, compiled regex, minimum Shannon entropy or None)``.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float | None]] = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), None),
    ("aws-secret-key", re.compile(r"[A-Za-z0-9/+=]{40}"), 4.5),
    ("github-token", re.compile(r"(gh[ps]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})"), None),
    ("openai-key", re.compile(r"sk-[A-Za-z0-9]{20,}"), None),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9-]{20,}"), None),
    ("stripe-key", re.compile(r"(sk|pk|rk)_(test|live)_[A-Za-z0-9]{24,}"), None),
    ("private-key-header", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), None),
    ("jwt-token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), None),
    ("slack-token", re.compile(r"xox[bpoas]-[A-Za-z0-9-]+"), None),
    ("database-url", re.compile(r"(postgres|mysql|mongodb|redis)://[^\s]+"), None),
]

#: Filesystem locations whose mere mention is a sensitivity signal. Mirrors the
#: paths mcpwall blocks outright, but here they only contribute a score -- the
#: point is to feed the HMM a gradient, not to make a per-call allow/deny call.
SENSITIVE_PATH_RE = re.compile(
    r"(\.ssh/|\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.env($|\.|\b)|\.aws/credentials|\.npmrc"
    r"|\.docker/config\.json|\.kube/config|\.gnupg/|/etc/passwd|/etc/shadow"
    r"|\.git-credentials|\.netrc|\.pgpass)",
    re.IGNORECASE,
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

#: Values that authorise movement of money or identify a person. Table II's PS
#: bucket is "credentials, paths, URLs, encoded data", which does not literally
#: cover a bank account -- yet section V-B calls S1's ``add_payee`` "a
#: high-sensitivity WRITE", and its only notable parameter is an attacker-controlled
#: recipient. Read broadly, "credentials" means anything that authorises an action,
#: so financial identifiers belong in the same bucket. Kept as a separate,
#: separately-weighted category so a deployment can disable it outright.
#: A bare run of digits is deliberately *not* enough. An early version matched
#: ``\d{8,17}`` and scored a WhatsApp phone number as a financial identifier,
#: pushing a benign message to Exfiltration. Evidence has to be structural (a
#: well-formed IBAN or card number) or lexical (a field actually named for money).
FINANCIAL_VALUE_RE = re.compile(
    r"(\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"  # IBAN
    r"|\b(?:\d[ -]?){13,19}\b"  # payment card
    r"|\b(?:account|routing|iban|swift|sort_?code|card_?number|payee)\b)",
    re.IGNORECASE,
)

#: Personal contact identifiers. Weighted well below credentials -- an email
#: address is routine in a mail workflow and must not by itself trip rule R1.
CONTACT_VALUE_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")

#: A base64-ish run long enough to be carrying a payload rather than an id.
ENCODED_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
HEX_BLOB_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")

#: Hosts that are normal destinations for developer tooling. Used only to damp
#: the URL signal -- an external URL is interesting, a package registry is not.
DEFAULT_BENIGN_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "raw.githubusercontent.com",
    }
)


@dataclass(frozen=True)
class SensitivityWeights:
    """Contribution of each signal to Parameter Sensitivity (feature dim 5).

    Table II describes PS as a "weighted sum: credentials, paths, URLs, encoded
    data". The paper does not publish the weights, so these are the design-spec
    defaults; every one is configurable.

    ``secret`` dominates because a literal credential in an argument is the
    strongest single indicator available. ``path`` sits just above the R1
    threshold (0.30) by design: reading ``~/.ssh/config`` must on its own count
    as "sensitive data access".
    """

    secret: float = 0.50
    #: Financial identifiers sit just under credentials: an account number does not
    #: authenticate, but it does direct where value goes. Set to 0.0 to disable.
    financial: float = 0.45
    path: float = 0.35
    encoded: float = 0.25
    url: float = 0.20
    external_url_bonus: float = 0.10
    #: Low by design. Email addresses are ubiquitous in legitimate workflows.
    contact: float = 0.10


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character.

    Used to suppress the ``aws-secret-key`` pattern, which is just "40 base64
    characters" and would otherwise match ordinary hashes and identifiers.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_base64(value: str) -> bool:
    """True if ``value`` decodes as base64 into something non-trivial.

    A length check alone flags every long hex id, so decode and require the
    result to be substantial.
    """
    if len(value) < 32 or len(value) % 4:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= 16


class ToolClassifier:
    """Maps a tool name to its Tool Category.

    Patterns are ordered; the first match wins. Passing ``patterns`` replaces the
    defaults wholesale, which is how a deployment adapts ChainWatch to a server
    whose naming conventions differ.
    """

    def __init__(self, patterns: Iterable[tuple[str, ToolCategory]] | None = None) -> None:
        self._patterns = list(patterns) if patterns is not None else list(DEFAULT_CATEGORY_PATTERNS)

    def classify(self, tool_name: str, description: str | None = None) -> ToolCategory:
        """Return the category for ``tool_name``.

        ``description`` is accepted so a future refinement can consult the tool's
        own text, but name matching is deliberately the only signal today: tool
        descriptions are attacker-controlled (section II-A), so trusting them
        would hand the classifier to the adversary.
        """
        name = tool_name.strip().lower()
        for pattern, category in self._patterns:
            if fnmatch.fnmatchcase(name, pattern):
                return category
        return ToolCategory.READ


@dataclass
class SensitivityScorer:
    """Scores argument payloads for Parameter Sensitivity (feature dim 5)."""

    weights: SensitivityWeights = field(default_factory=SensitivityWeights)
    benign_hosts: frozenset[str] = DEFAULT_BENIGN_HOSTS

    def score(self, arguments: Any) -> float:
        """Return sensitivity in [0, 1] for a tool call's arguments.

        Signals accumulate, then clamp. Accumulating rather than taking a maximum
        means a call that both reads a credential path *and* posts to an external
        URL outscores one that only does the former -- which is the escalation
        gradient stages 4 through 6 are built on.
        """
        text = "\n".join(self._iter_strings(arguments))
        if not text:
            return 0.0

        total = 0.0
        if self.contains_secret(text):
            total += self.weights.secret
        if FINANCIAL_VALUE_RE.search(text):
            total += self.weights.financial
        if SENSITIVE_PATH_RE.search(text):
            total += self.weights.path
        if self.contains_encoded_blob(text):
            total += self.weights.encoded
        if CONTACT_VALUE_RE.search(text):
            total += self.weights.contact

        urls = URL_RE.findall(text)
        if urls:
            total += self.weights.url
            if any(self._is_external(url) for url in urls):
                total += self.weights.external_url_bonus

        return min(1.0, total)

    def contains_secret(self, text: str) -> bool:
        """True if any mcpwall secret pattern matches, respecting entropy floors."""
        for _name, pattern, entropy_threshold in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                if entropy_threshold is None:
                    return True
                if shannon_entropy(match.group(0)) >= entropy_threshold:
                    return True
        return False

    def contains_encoded_blob(self, text: str) -> bool:
        """True if the text carries a base64 or long hex payload."""
        if HEX_BLOB_RE.search(text):
            return True
        return any(looks_base64(candidate) for candidate in ENCODED_BLOB_RE.findall(text))

    def _is_external(self, url: str) -> bool:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
        host = host.split("@")[-1].split(":")[0].lower()
        return host not in self.benign_hosts

    def _iter_strings(self, value: Any) -> Iterable[str]:
        """Flatten arbitrary JSON into the string leaves, keys included.

        Keys matter: ``{"ssh_private_key": "..."}`` is a signal even when the
        value itself is opaque.
        """
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield str(key)
                yield from self._iter_strings(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                yield from self._iter_strings(item)
        elif value is not None:
            yield str(value)
