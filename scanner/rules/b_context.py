import json
import re
from bs4 import BeautifulSoup
from .base import Rule, Verdict

MARKER = "window.__xss_fired=1"
HTML_ENTITY = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;")

# Non-greedy so it stops at the first </script>, matching browser behavior.
SCRIPT_BLOCK_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)


class RuleB(Rule):
    name = "B_landing_spot"

    def evaluate(self, row):
        body = row["body"]

        ctype = self._content_type(row["headers"])
        if "text/html" not in ctype:
            return Verdict(False, f"non-HTML response ({ctype})")
        if MARKER not in body:
            return Verdict(False, "marker not present in response")

        # 1. Scan RAW HTML for <script> blocks (BeautifulSoup hides nested tags)
        for m in SCRIPT_BLOCK_RE.finditer(body):
            content = m.group(1)
            if MARKER not in content:
                continue
            if any(e in content for e in HTML_ENTITY):
                continue
            pos = content.find(MARKER)
            if self._in_js_string(content, pos):
                continue
            # Any unescaped '<' before the marker means HTML was injected
            # into the JS -> the block is syntactically broken and the
            # browser will refuse to run it.
            if "<" in content[:pos]:
                continue
            return Verdict(True, "marker landed in executable <script> body")

        # 2. Marker in an on* handler (BeautifulSoup handles attributes fine)
        soup = BeautifulSoup(body, "html5lib")
        for tag in soup.find_all(True):
            for attr, val in (tag.attrs or {}).items():
                if isinstance(val, list):
                    val = " ".join(val)
                if not isinstance(val, str):
                    continue
                if not attr.lower().startswith("on"):
                    continue
                if MARKER in val and not any(e in val for e in HTML_ENTITY):
                    return Verdict(True, f"marker landed in {attr} attribute")

        # 3. Marker in a javascript: URL - scan RAW HTML
        for m in re.finditer(r"javascript:([^\"'<>\s]*)", body):
            url_body = m.group(1)
            if MARKER not in url_body:
                continue
            if any(e in url_body for e in HTML_ENTITY):
                continue
            return Verdict(True, "marker landed in javascript: URL")

        return Verdict(False, "marker landed in non-executable position")

    @staticmethod
    def _in_js_string(js, pos):
        """True if the char at `pos` is inside a JS string OR if the JS is
        syntactically broken before `pos` (e.g. a stray backslash or quote)."""
        in_single = in_double = False
        i = 0
        while i < pos:
            c = js[i]
            if c == "\\":
                # Backslash outside any string is a JS syntax error.
                # Treat as "don't trust this" so we skip it.
                if not in_single and not in_double:
                    return True
                i += 2  # skip escaped character
                continue
            if not in_double and c == "'":
                in_single = not in_single
            elif not in_single and c == '"':
                in_double = not in_double
            i += 1
        return in_single or in_double

    @staticmethod
    def _content_type(headers_json):
        try:
            h = json.loads(headers_json)
        except Exception:
            return ""
        for k, v in h.items():
            if k.lower() == "content-type":
                return v.lower()
        return ""