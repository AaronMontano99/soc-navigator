# SOC Navigator Console — Design Reference

The current frontend implements an approved design (a Claude Design interactive prototype,
reviewed and recreated by hand into this repo's vanilla HTML/CSS/JS — see `frontend/`). This doc
describes what's actually shipped, so it stays a reference rather than aspirational spec.

## Palette

Colors are held to a strict rule: **warm color means severity, and nothing else.**

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#0b0f17` | Page background |
| `--panel` / `--panel-2` | `#10151f` / `#171f30` | Panels, raised surfaces |
| `--border` | `#1f2937` | Hairlines |
| `--critical` | `#ef4444` | Critical risk only |
| `--high` | `#f68d1f` | High risk, and the single UI accent (CTAs, active nav, links) |
| `--medium` | `#eab308` | Medium risk |
| `--low` | `#4f8cf0` | Low risk |
| `--good` | `#34d399` | Confirmed-benign verdicts, completed checklist items |
| `--text` / `--text-dim` | `#e5e9f0` / `#8a93a6` | Primary / secondary text |

Reusing `--high` as both "high severity" and "the app's one accent color" is deliberate — it keeps
the palette small and means every orange element in the UI is, in some sense, calling for
attention, whether that's a risk badge or a "run this" button.

## Typography

`IBM Plex Sans` for body/UI copy, `IBM Plex Mono` for anything data-shaped: badges, timestamps,
technique IDs, code blocks, table headers, nav labels. Loaded from Google Fonts with a system-font
fallback stack, so the app still looks correct with no network access. Structural labels (panel
titles, table headers, badges) are uppercase mono with wide letter-spacing — the "instrument
readout" voice that carries most of the app's personality, since color is reserved for severity.

## Layout

Three-column shell: a fixed ~190px sidebar (grouped nav: SOC / DETECTION / LAB / LEARN), a fluid
content column, and a ~320px AI Investigation Assistant drawer on the right that's context-aware —
grounded in whatever incident is currently open, with a `Grounded in <incident-id>` label so it's
never ambiguous what data the assistant is reasoning over.

Every content page follows the same shape: a header (title + one-line description), stat tiles or
a summary panel, then one or more `panel` blocks holding tables or grouped content. Incident detail
adds a second layer — an Analyst View / Security Leader View toggle, and (in Analyst View) a
Summary / Timeline / Evidence / Detection / ATT&CK / NIST tab strip — all rendering the same
underlying `GET /api/incidents/{id}` payload.

## Depth and shape

Flat panels with a single hairline border — no shadows, no gradients. Corners are small-radius
throughout (4–6px); rounding is not used as a signal the way color is. Rows and cards get a
left accent border (severity color) rather than a background tint, so a table stays scannable at
a glance even before reading any text.

## Where the design lives in code

- `frontend/styles.css` — all tokens and component styles
- `frontend/index.html` — the three-column shell
- `frontend/views.js` — Overview / Incidents / Alerts / Rules / Coverage / Attack Lab / Architecture / About
- `frontend/incident.js` — incident detail, both presentations, all six analyst sub-tabs
- `frontend/app.js` — routing and the AI drawer
