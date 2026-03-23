# Changelog

## [3.1.0] — 2026-03-23

### Fixed
- False positives: platforms with generic `"404"` not-found text now rely on HTTP status code instead of body matching
- HTML report save error caused by unescaped CSS braces inside Python f-strings
- Dork filter regex too narrow — blank-field patterns like `"" OR ""` and bare `site:` now correctly suppressed

### Changed
- Dork section header and count line suppressed when no valid queries are generated
- Variant generator now prints a compact preview (seeds, sample variants, total count) before scanning


## [3.0.0] — 2026-03-22

### Added
- Async engine (`aiohttp`) with 20 concurrent requests — ~10× faster than v2
- Platform coverage expanded from 32 to 80+ across 10 categories
- Per-platform `risk` w.eight (1–5) and `category` tag
- Username variant generator (leet, suffixes, name-derived handles)
- Email intel: Gravatar hash, MX records, HIBP stub
- DNS enumeration: A, MX, NS, TXT records
- WHOIS lookup: registrar, creation date, org, country
- IP analysis: reverse DNS + Shodan stub
- Dork generator expanded to 8 categories with clickable HTML links
- Four report formats: JSON, CSV, TXT, HTML (dark-mode dashboard)
- Checkpoint / resume support for interrupted scans
- CVSS-inspired exposure score (0–100) with CRITICAL / HIGH / MEDIUM / LOW rating
- OPSEC pre-flight check with external IP display


## [2.0.0]

### Added
- 32 platforms across 6 categories
- Synchronous HTTP scanning with browser user-agent rotation
- Cross-platform username correlation


- Google dork generation and browser auto-open
- Weighted exposure score (0–100)
- JSON + TXT report export
