import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.b_context import RuleB, SCRIPT_BLOCK_RE, MARKER

# The exact 6 bodies from the earlier diagnostic
bodies = [
    '<script><script>window.__xss_fired=1;/*XSSf27b5b61*/</script></script>',
    '<script>\\"><script>window.__xss_fired=1;/*XSSf27b5b61*/</script></script>',
    "<script>\\'><script>window.__xss_fired=1;/*XSSf27b5b61*/</script></script>",
    '<script><img src=x onerror=\\"window.__xss_fired=1\\" alt=\\"XSSf27b5b61\\"></script>',
    '<script>\\";window.__xss_fired=1;//XSSf27b5b61</script>',
    '<script>--><script>window.__xss_fired=1;/*XSSf27b5b61*/</script></script>',
]

rule = RuleB()

for i, body in enumerate(bodies, 1):
    print(f"\n=== Body {i} ===")
    print(f"BODY: {body!r}")
    row = {
        "body": body,
        "headers": '{"Content-Type": "text/html"}',
        "token": "XSSf27b5b61",
    }
    v = rule.evaluate(row)
    print(f"VERDICT: exploitable={v.exploitable} reason={v.reason}")

    # Show what the script-block regex sees
    for j, m in enumerate(SCRIPT_BLOCK_RE.finditer(body)):
        content = m.group(1)
        if MARKER not in content:
            print(f"  script match {j}: no marker in content")
            continue
        pos = content.find(MARKER)
        print(f"  script match {j}: content={content!r}")
        print(f"    pos={pos}  content[:pos]={content[:pos]!r}")
        print(f"    in_js_string={rule._in_js_string(content, pos)}")
        print(f"    has_lt_before={'<' in content[:pos]}")