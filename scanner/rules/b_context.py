import json
from bs4 import BeautifulSoup
from .base import Rule, Verdict

# The actual executable marker that every payload embeds.
# If this appears in an executable position, the payload will run.
MARKER = "window.__xss_fired=1"

# HTML entity markers that indicate the payload was HTML-escaped (inert).
HTML_ENTITY = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;")


class RuleB(Rule):
    name = "B_landing_spot"

    def evaluate(self, row):
        body = row["body"]

        ctype = self._content_type(row["headers"])
        if "text/html" not in ctype:
            return Verdict(False, f"non-HTML response ({ctype})")

        if MARKER not in body:
            return Verdict(False, "marker not present in response")

        soup = BeautifulSoup(body, "html5lib")

        # 1. Marker inside <script> body (executable JS)
        for script in soup.find_all("script"):
            content = script.string or "".join(script.strings)
            if not content or MARKER not in content:
                continue
            if any(e in content for e in HTML_ENTITY):
                continue  # payload was HTML-escaped inside the script
            return Verdict(True, "marker landed in executable <script> body")

        # 2. Marker inside an on* event handler
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

        # 3. Marker inside a javascript: URL
        for tag in soup.find_all(True):
            for attr in ("href", "src", "action"):
                val = tag.get(attr)
                if not isinstance(val, str):
                    continue
                if not val.lower().startswith("javascript:"):
                    continue
                if MARKER in val and not any(e in val for e in HTML_ENTITY):
                    return Verdict(True, f"marker landed in javascript: {attr}")

        return Verdict(False, "marker landed in non-executable position")

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