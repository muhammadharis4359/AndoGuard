"""Assemble standalone dashboard.html containing inlined CSS and JavaScript."""

from pathlib import Path


def main() -> None:
    html = Path("andoguard/dashboard/static/index.html").read_text(encoding="utf-8")
    css = Path("andoguard/dashboard/static/dashboard.css").read_text(encoding="utf-8")
    js = Path("andoguard/dashboard/static/dashboard.js").read_text(encoding="utf-8")

    standalone = html.replace('<link rel="stylesheet" href="dashboard.css">', f"<style>\n{css}\n</style>")
    standalone = standalone.replace('<script src="dashboard.js"></script>', f"<script>\n{js}\n</script>")

    out_file = Path("dashboard.html")
    out_file.write_text(standalone, encoding="utf-8")
    print(f"Successfully generated standalone {out_file} ({out_file.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
