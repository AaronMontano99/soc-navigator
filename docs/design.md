---
version: alpha
name: SOC Navigator Console Design System
description: >
  A dark security-operations console built from beveled instrument plates,
  a carbon command layer, and rationed warm signal color reserved strictly
  for severity and action. Adapted from a Y2K "console hardware" reference
  system (brushed-metal chassis, chamfered plates, carbon command slabs,
  rationed warm accent) — the structural grammar is kept, the literal skin
  is not: no pastel chrome, no mascot, no game box-art type. The result
  should read as instrument-panel hardware for a SOC, not a toy.

colors:
  critical: "#ef4444"     # Alert Red — critical risk badges, destructive states
  high: "#f68d1f"          # Signal Orange — high risk badges, primary forward/action accent
  medium: "#eab308"        # Amber — medium risk badges, utility buttons
  low: "#64748b"           # Slate — low risk, inactive/neutral chrome
  good: "#34d399"          # Confirmed-safe green — benign verdicts, completed checklist items
  accent: "#38bdf8"        # Console Cyan — links, focus rings, AI assistant voice (kept distinct from severity colors on purpose)
  carbon: "#05070c"         # Command-slab black — header bar, code/evidence blocks
  chassis: "#0b0f17"         # Base canvas — page background
  plate: "#121826"            # Panel body ("console plate")
  plate-raised: "#171f30"      # Raised chip / inset surface, one step brighter than plate
  bevel-hi: "#2a3550"           # Bevel top highlight (brushed edge)
  bevel-lo: "#05070c"            # Bevel bottom shadow line
  border: "#232c40"               # Structural hairline
  text: "#e5e9f0"
  text-dim: "#8a93a6"
  on-accent: "#041018"              # Text on bright accent/signal fills

typography:
  panel-title:
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace"
    fontSize: 13px
    fontWeight: 700
    letterSpacing: 0.08em
    textTransform: uppercase
  nav-label:
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace"
    fontSize: 12px
    fontWeight: 700
    letterSpacing: 0.05em
    textTransform: uppercase
  display:
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace"
    fontSize: 20px
    fontWeight: 700
    letterSpacing: 0.08em
    textTransform: uppercase
  body:
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace"
    fontSize: 13px
    fontWeight: 400
  micro:
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace"
    fontSize: 11px
    fontWeight: 400
    color: "{colors.text-dim}"

rounded:
  none: 0px
  xs: 4px
  sm: 6px
  md: 8px
  lg: 10px
  full: 9999px

spacing:
  xxs: 2px
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
  xxl: 32px

elevation:
  0-inset:
    description: "Recessed into chassis — evidence/raw-field code blocks, received chat bubbles"
    background: "{colors.carbon}"
    border: "1px solid {colors.border}"
  1-plate:
    description: "Flush panel — content panels, stat tiles"
    background: "{colors.plate}"
    borderTop: "1px solid {colors.bevel-hi}"
    borderBottom: "1px solid {colors.bevel-lo}"
  2-raised-chip:
    description: "Beveled control — buttons, badges, active tabs"
    background: "{colors.plate-raised}"
    borderTop: "1px solid {colors.bevel-hi}"
    boxShadow: "0 2px 0 {colors.bevel-lo}"
  3-command-slab:
    description: "Carbon near-black, sits above the chrome — header, scenario bar"
    background: "{colors.carbon}"
    borderBottom: "1px solid {colors.border}"

components:
  topbar:
    backgroundColor: "{colors.carbon}"
    textColor: "{colors.text}"
    typography: "{typography.display}"
    elevation: "3-command-slab"
    chamfer: true
  scenario-btn:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.text}"
    typography: "{typography.nav-label}"
    elevation: "2-raised-chip"
    rounded: "{rounded.xs}"
  panel:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.text}"
    elevation: "1-plate"
    rounded: "{rounded.sm}"
    chamfer: true
    padding: "{spacing.lg}"
  stat-tile:
    backgroundColor: "{colors.plate}"
    elevation: "1-plate"
    rounded: "{rounded.sm}"
    padding: "{spacing.md}"
  incident-card:
    backgroundColor: "{colors.plate}"
    elevation: "1-plate"
    leftEdgeColor: "severity color (critical/high/medium/low)"
    rounded: "{rounded.sm}"
  risk-badge:
    rounded: "{rounded.full}"
    typography: "{typography.nav-label}"
    fill: "severity color at 15% opacity, text at full severity color"
  view-toggle-btn:
    backgroundColor: "{colors.plate}"
    activeColor: "{colors.accent}"
    elevation: "2-raised-chip"
    rounded: "{rounded.xs}"
  evidence-block:
    backgroundColor: "{colors.plate-raised}"
    elevation: "0-inset"
    rounded: "{rounded.sm}"
  raw-fields-block:
    backgroundColor: "{colors.carbon}"
    textColor: "{colors.text-dim}"
    elevation: "0-inset"
    typography: "{typography.micro}"
  nist-checklist-item:
    typography: "{typography.micro}"
    doneColor: "{colors.good}"
    pendingColor: "{colors.high}"
    naColor: "{colors.text-dim}"
  chat-bubble-user:
    backgroundColor: "{colors.plate-raised}"
    textColor: "{colors.accent}"
  chat-bubble-ai:
    backgroundColor: "{colors.plate-raised}"
    textColor: "{colors.text}"
    elevation: "0-inset"

---

# SOC Navigator Console Design System

## Origin and adaptation

This system is adapted from a Y2K console-hardware reference design (brushed-metal chassis,
carbon command slabs, chamfered plates, rationed warm signal color). The reference was built for
a consumer gaming-brand site — pastel periwinkle chrome, a mascot speech bubble, box-art wordmarks
with heavy outlines. None of that survives the adaptation, because it would actively undercut what
this project is for: convincing a security audience this is a serious operations tool, not a toy.

What *does* survive, because it's structurally sound for a SOC console regardless of brand: the
idea that the interface is **assembled hardware, not a stack of flat cards** — every region is a
beveled plate with a highlighted top edge and a shadow line beneath; a **carbon command layer**
sits visually "above" the content chrome for global controls (the header, the scenario launcher);
corners default to **sharp, occasionally chamfered**, never uniformly rounded, because roundness
is reserved for a small set of true controls (badges, pills); and **warm color is rationed to mean
one thing** — here, that one thing is risk severity and forward action, never decoration.

## Colors

Three layers, same discipline as the source system, different palette:

- **Chassis** (`{colors.chassis}`) — the page background, near-black navy.
- **Plates** (`{colors.plate}`, `{colors.plate-raised}`) — every panel, tile, and card is inset
  into the chassis as a plate, one step brighter than the background, with a `{colors.bevel-hi}`
  highlight on its top edge and a `{colors.bevel-lo}` shadow line beneath — the bevel is what
  makes the page read as instrument panels rather than a flat document.
- **Carbon command layer** (`{colors.carbon}`) — the header/topbar and any raw evidence/code
  surfaces. This is the "system," as distinct from "content."

Warm color is rationed exactly the way the reference system insists on, just remapped to this
domain's actual semantics: **severity is the signal**. `{colors.critical}` red, `{colors.high}`
orange, `{colors.medium}` amber, and `{colors.low}` slate are risk levels first — they are never
used decoratively. `{colors.accent}` cyan is held back for a second job only: links, focus states,
and the AI assistant's voice, so it's never ambiguous with a risk badge. `{colors.good}` green is
reserved for confirmed-benign verdicts and completed checklist items — the one place "calm" gets a
color of its own.

## Typography

Monospace throughout (`ui-monospace` / SF Mono stack) — for a SOC console this isn't a period
constraint the way it was for the source system's web-safe Inter, it's the right choice on the
merits: monospace reads as a terminal/instrument readout, which is exactly the register this tool
wants. Structural labels (panel titles, nav labels, button text) are uppercase with wide tracking,
carrying the same "silkscreened legend" voice the reference system built its chrome labels around.
Body copy and raw event data stay small and quiet so the hierarchy is carried by labels and color,
not font-size escalation.

## Shapes and elevation

Depth is bevel, not blur — every plate gets a lighter top border and a darker bottom border/shadow
instead of a soft drop-shadow. Corners default to sharp; the topbar and top-level panels carry a
small chamfer (a corner cut, not a curve) on their top edges as the one deliberate "manufactured
hardware" flourish, and full rounding is spent only on badges, pills, and the risk-level indicator
dots — never on general containers.

## Do's and Don'ts

**Do**
- Give every panel a real bevel: brighter top edge, `{colors.bevel-lo}` shadow line beneath.
- Let risk severity be the only warm color in the interface — critical/high/medium each mean
  exactly one thing and are never reused decoratively.
- Keep panel titles and button labels uppercase, tracked, monospace — the console's "legend" voice.
- Default to sharp corners; spend roundness only on badges, pills, and status dots.

**Don't**
- Don't add a second warm accent that competes with the severity palette — it must stay legible
  as "how bad is this," not become generic brand color.
- Don't introduce soft blurred drop-shadows — bevel borders only.
- Don't round every corner into a uniform card system — that erases the "instrument panel" read
  this system exists to create.
- Don't add mascot, illustration, or decorative photography — this is an operations tool; the only
  imagery is data.
