from flask import Flask, request, make_response
import html, csv, os

app = Flask(__name__)

# Load the matrix
MATRIX = []
matrix_path = os.path.join(os.path.dirname(__file__), "matrix.csv")
with open(matrix_path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        MATRIX.append(row)


def apply_defense(value, defense):
    """Simulates different server-side defenses."""
    if defense == "none":
        return value
    if defense == "html_escape":
        return html.escape(value, quote=True)
    if defense == "attr_escape":
        return html.escape(value, quote=True).replace("'", "&#x27;")
    if defense == "js_escape":
        return (value.replace("\\", "\\\\")
                     .replace("'", "\\'")
                     .replace('"', '\\"'))
    return value


@app.route("/")
def home():
    """Homepage listing all test cases."""
    out = "<h1>XSS Lab Test Cases</h1><ul>"
    for row in MATRIX:
        out += f'<li><a href="/page/{row["id"]}">{row["id"]}</a> - {row["context"]} ({row["defense"]})</li>'
    out += "</ul>"
    return out


@app.route("/page/<case_id>")
def page(case_id):
    row = next((r for r in MATRIX if r["id"] == case_id), None)
    if not row:
        return "Case not found", 404

    value = request.args.get("q", "")
    value = apply_defense(value, row["defense"])

    # Replace the placeholder with our value — no Jinja2 templating
    body = row["template"].replace("{{INPUT}}", value)

    resp = make_response(body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"

    if row["csp"] != "none":
        resp.headers["Content-Security-Policy"] = row["csp"]

    return resp


if __name__ == "__main__":
    app.run(port=5000, debug=False)