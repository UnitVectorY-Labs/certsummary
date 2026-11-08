# UVY Design adoption

Reviewed against the human-readable [UVY Design guidance](https://github.com/UnitVectorY-Labs/uvy-design/tree/5f8bd54490c2d6fbba7ac422894bb8d27d83bde5) at commit `5f8bd54490c2d6fbba7ac422894bb8d27d83bde5`. The design repository is guidance, not a versioned dependency; this application owns its implementation.

The interface uses system fonts, blue project and section titles, orange heading underlines and a primary action icon, neutral panels, local Tabler icons, and light and dark themes. The existing two-pane workspace, certificate parsing, fragment sharing, crt.sh links and footer destinations remain. The theme follows system preference until an explicit choice is saved in a host-only cookie. The page remains usable without JavaScript or saved preferences.

The application retains CSS and theme code originally copied from the former UVY Design v0.1.0 assets, with application-specific styling in `app/style.css`. They are maintained locally; no design assets are fetched at runtime. Their original license and the licenses for jsrsasign and Tabler icons are in `app/THIRD_PARTY_NOTICES.txt`. The vendored jsrsasign matches the original CDN SRI.

Run `node --test tests/` for local checks. Review normal workflows, light and dark themes, keyboard focus and narrow screens when changing the interface. Screenshots support review but do not establish accessibility compliance.
