# IFDA official site

A single self-contained static page (`index.html`) for the project — no
build step, no external CDN/font/script dependencies (consistent with the
rest of the project's air-gapped-friendly philosophy). Bilingual (EN/中文,
toggle in the nav) and light/dark themed, using the same color palette as
the product's own web UI (`service/web/index.html`, "midnight" theme).

## Preview locally

```bash
cd html && python3 -m http.server 8090
# open http://localhost:8090
```

## Editing

- All copy lives in the `I18N` object near the bottom of `index.html`
  (`{en: "...", zh: "..."}` per key); markup references it via
  `data-i18n="key"`. Keep both languages in sync — see `html/README.md`'s
  own repo for no external check, but a quick way to verify nothing is
  missing:

  ```bash
  python3 - <<'EOF'
  import re
  html = open("index.html", encoding="utf-8").read()
  used = set(re.findall(r'data-i18n="([^"]+)"', html))
  script = html[html.index("const I18N"):html.index("(function")]
  defined = set(re.findall(r'([A-Za-z0-9_]+)\s*:\s*\{', script))
  print("missing:", used - defined or "none")
  print("unused:", defined - used or "none")
  EOF
  ```
- The UI-preview section is a hand-drawn CSS mockup, not a real screenshot
  — update it if the actual dashboard layout changes meaningfully enough
  that it'd mislead.
- Feature copy is sourced from `README.md` / `CHANGELOG.md` / `PROGRESS.md`
  at the repo root — re-check those when adding a new capability here.
