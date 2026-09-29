import json
from .base import Rule, Verdict


class RuleC(Rule):
    name = "C_csp_check"

    # Rule C only *downgrades* Rule B findings. It never adds new ones.
    def __init__(self, upstream_rule=None):
        from .b_context import RuleB
        self.upstream = upstream_rule or RuleB()

    def evaluate(self, row):
        # 1. Run the upstream rule first
        upstream_verdict = self.upstream.evaluate(row)
        if not upstream_verdict.exploitable:
            return Verdict(False, f"upstream: {upstream_verdict.reason}")

        # 2. Read the enforced CSP header
        csp = self._get_csp(row["headers"])

        # No CSP → nothing to mitigate
        if csp is None:
            return Verdict(True, f"exploitable (no CSP); {upstream_verdict.reason}")

        # 3. Parse the CSP and figure out the effective script policy
        directives = self._parse_csp(csp)
        script_policy = self._effective_script_policy(directives)

        # 4. If no script-src or default-src → CSP doesn't restrict scripts
        if script_policy is None:
            return Verdict(True, f"exploitable (CSP allows); {upstream_verdict.reason}")

        # 5. Is inline script execution allowed?
        if self._allows_inline(script_policy):
            return Verdict(True, f"exploitable ('unsafe-inline' allows); {upstream_verdict.reason}")
        else:
            return Verdict(False, f"MITIGATED by CSP ({csp!r})")

    # ---- CSP parsing helpers ----

    @staticmethod
    def _get_csp(headers_json):
        try:
            h = json.loads(headers_json)
        except Exception:
            return None
        for k, v in h.items():
            if k.lower() == "content-security-policy":
                return v
        return None

    @staticmethod
    def _parse_csp(csp):
        """Return {directive_name: [values...]}."""
        out = {}
        for part in csp.split(";"):
            toks = part.strip().split()
            if not toks:
                continue
            out[toks[0].lower()] = [t.lower() for t in toks[1:]]
        return out

    @staticmethod
    def _effective_script_policy(directives):
        """Per CSP spec: script-src-elem > script-src > default-src."""
        for name in ("script-src-elem", "script-src", "default-src"):
            if name in directives:
                return directives[name]
        return None

    @staticmethod
    def _allows_inline(policy):
        """Does this policy allow inline <script> execution?"""
        if "'none'" in policy:
            return False
        # 'strict-dynamic' ignores 'unsafe-inline' (CSP3 behavior)
        if "'strict-dynamic'" in policy:
            return False
        # Nonce present → CSP3 requires nonce on every inline script;
        # 'unsafe-inline' is ignored when a nonce/hash is present.
        if any(v.startswith("'nonce-") for v in policy):
            return False
        if any(v.startswith("'sha256-") or v.startswith("'sha384-")
               or v.startswith("'sha512-") for v in policy):
            return False
        return "'unsafe-inline'" in policy