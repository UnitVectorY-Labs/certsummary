# UVY Design v0.1.0 adoption

Source release: https://github.com/UnitVectorY-Labs/uvy-design/releases/tag/v0.1.0

Pinned source commit: `396a65021c2bcab8dbcb3d1bb4cb498c807a4396`.

Canonical tokens, the theme controller and the opt-in element treatments are copied verbatim into `app/assets/`: `uvy-tokens.css`, `uvy-theme.js` and `uvy-elements.css` (the last is used for the theme toggle, primary button, footer and icon sizing). `app/style.css` is the app-specific adapter that maps the existing selectors to the tokens. The official Tabler moon, sun, copy and external-link SVG paths are inlined in `index.html` and the crt.sh link output; the MIT icon notice is retained in `app/THIRD_PARTY_NOTICES.txt`. jsrsasign 11.1.0 is vendored unmodified at `app/vendor/jsrsasign-all-min.js`; its SHA-512 matches the SRI previously pinned for the cdnjs copy, so the CDN `<script>` was replaced with the local file. No HTMX, framework or external runtime dependency is introduced.

## Preserved behavior and scope

The certificate input/result workbench is unchanged: same two-pane desktop layout (stacked on mobile with both panes fully usable), same textarea, same parsing, same Copy Link fragment encoding/decoding, same `aria-live` "Link copied to clipboard!" feedback, same "No certificate processed yet." empty state, same invalid-input error text, and same crt.sh links per fingerprint. Masthead identity, footer links (UnitVectorY Labs | MIT License | certsummary on GitHub) and all URLs are preserved. Markup changes are limited to `lang="en"`, a screen-reader label for the textarea, the theme button, and styling hooks (`class="error-state"` replacing inline `color:red`). `script.js` logic is unchanged; the only output change is the official inline external-link SVG replacing the decorative emoji in crt.sh links.

Theme behavior follows the interaction contract: first visit follows the OS, the top-right binary button writes a host-only `uvy-theme` cookie (`Path=/`, `SameSite=Lax`, one year, `Secure` on HTTPS), and no older localStorage handler exists. `uvy-theme.js` loads synchronously in `<head>` before `uvy-tokens.css`, `uvy-elements.css` and the adapter CSS.

## Verification and screenshots

Run `node --test tests/` (node v26; no package.json needed). Tests cover: zero external runtime references in `index.html`, the vendored jsrsasign SHA-512 matching the pinned SRI, byte-identical v0.1.0 shared assets, retained fragment encode/decode and KJUR/X509 usage, head load order, and the theme button markup. Browser checks (see the evidence branch): parsed output text parity with the baseline for an identical public sample certificate, fingerprints verified against OpenSSL, Copy Link clipboard round-trip, invalid-PEM error state, cookie persistence and OS defaults, 320/390/768/1440px fit with both panes, keyboard focus order, no-JS baseline, and zero external runtime requests. The PR embeds the complete before/after desktop/mobile light/dark matrix for the four major states (empty, valid PEM, invalid PEM, fragment-loaded) plus scrolled and 320px supplements. Baseline has no dark mode; both OS preferences faithfully retain its original appearance. The baseline additionally loads jsrsasign from cdnjs — the after build removes that dependency entirely.

No screenshots are committed to this application. Evidence is hosted in the design repository's `evidence/certsummary-v0.1.0` branch and linked immutably from the PR.

## Update procedure

Choose a reviewed future release, verify archive checksums and file hashes, then replace only the canonical copied files in `app/assets/`. Review source diffs and update this record; keep app-specific adapter changes in `app/style.css`. Rebuild nothing (static site), rerun `node --test tests/`, and repeat the browser/evidence checks before updating. Never fetch design assets at browser runtime or from a mutable branch.

## Copied-file SHA-256

- `assets/uvy-tokens.css`: `0e97baaece886e0015c4238eaf7dbed9ea68f330c0f50729311c43b4a5a98533`
- `assets/uvy-theme.js`: `b105c0ddec8c19b6a380a33ffa5f9f558ca49baa477921a1dee9596d77bc61ed`
- `assets/uvy-elements.css`: `b2f92292dd9317bb770be1a4c745c9a00b81b6cef39cbcac54d2fe192135b092`
- `vendor/jsrsasign-all-min.js`: `6ccedfb9896ef454a92b081f29c229ca2a4969189661dcfa43f0eac12cb981a6` (SHA-512 `sha512-Eu9j+HZBor7muHf6IDWoWZ8FKVr6nKe9eIIVR28NEte4Y4GiYRlke26XGdR/re81XE/FfLoLYYVkvNk5GY9RvQ==`)
- Design `LICENSE` (MIT, UnitVectorY-Labs): `00320f7ebea7d48c92ddabd067541e3a8d3c033deafb50ada6bf7a3a56f640dc`
