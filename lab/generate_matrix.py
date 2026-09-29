import csv
import os

# Define our testing dimensions
contexts = {
    "c01_html_body": "<p>You searched for: {{INPUT}}</p>",
    "c02_attr_double": "<input value=\"{{INPUT}}\">",
    "c03_attr_single": "<input value='{{INPUT}}'>",
    "c04_script_string": "<script>var x = '{{INPUT}}';</script>",
    "c05_script_body": "<script>{{INPUT}}</script>",
    "c06_comment": "<!-- {{INPUT}} -->",
    "c07_js_url": "<a href=\"javascript:{{INPUT}}\">click</a>",
}

defenses = ["none", "html_escape", "attr_escape", "js_escape"]
csps = ["none", "script-src 'self'", "script-src 'none'", "script-src 'unsafe-inline'"]

matrix = []
case_id = 1

# Generate all combinations
for c_name, template in contexts.items():
    for defense in defenses:
        for csp in csps:
            # We only need to test CSPs on vulnerable pages to save time
            if csp != "none" and defense != "none":
                continue
                
            matrix.append({
                "id": f"case{case_id:03d}",
                "context": c_name,
                "defense": defense,
                "csp": csp,
                "template": template
            })
            case_id += 1

# Write to CSV
os.makedirs("lab", exist_ok=True)
with open("lab/matrix.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["id", "context", "defense", "csp", "template"])
    writer.writeheader()
    writer.writerows(matrix)

print(f"✅ Generated {len(matrix)} test cases in lab/matrix.csv")