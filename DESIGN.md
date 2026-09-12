---
name: TUESDAY
description: Autonomous air-gapped SOC + host EDR command console (Sentinel) and adversary drill suite (RedTeam).
colors:
  brand-defensive: "#00E599"
  brand-defensive-dim: "#0C211A"
  brand-interactive: "#38BDF8"
  brand-interactive-dim: "#0D1F2C"
  brand-cognition: "#A78BFA"
  brand-cognition-dim: "#1A1633"
  danger: "#F43F5E"
  danger-dim: "#32151C"
  hostile-deep: "#BE123C"
  hostile-deep-hover: "#E11D48"
  attention: "#F59E0B"
  attention-dim: "#2E210F"
  neutral-void: "#06080D"
  neutral-surface: "#0B0E17"
  neutral-card: "#0D111A"
  neutral-ink: "#F8FAFC"
  neutral-muted: "#94A3B8"
  neutral-dim: "#7C8DB0"
  hairline: "#1C1F27"
  hairline-strong: "#21242C"
typography:
  display:
    fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: "clamp(1.5rem, 3vw, 2.25rem)"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: "1.05rem"
    fontWeight: 700
    lineHeight: 1.3
  title:
    fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.03em"
  body:
    fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: "0.82rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: "0.68rem"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.06em"
    textTransform: "uppercase"
  mono:
    fontFamily: "'JetBrains Mono', monospace"
    fontSize: "0.78rem"
    fontWeight: 500
    lineHeight: 1.5
rounded:
  sm: "6px"
  md: "10px"
  lg: "14px"
  xl: "20px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.brand-defensive-dim}"
    textColor: "{colors.brand-defensive}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
  button-primary-hover:
    backgroundColor: "#09352E"
    textColor: "{colors.brand-defensive}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
  button-danger:
    backgroundColor: "{colors.danger-dim}"
    textColor: "{colors.danger}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
  button-danger-hover:
    backgroundColor: "#3E1927"
    textColor: "{colors.danger}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
  button-ghost:
    backgroundColor: "#12151E"
    textColor: "{colors.neutral-muted}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
  input-search:
    backgroundColor: "#0A0D12"
    textColor: "{colors.neutral-ink}"
    rounded: "{rounded.sm}"
    padding: "0.65rem 0.9rem"
  card:
    backgroundColor: "{colors.neutral-card}"
    rounded: "{rounded.lg}"
    padding: "1.15rem"
  pill:
    backgroundColor: "#151820"
    textColor: "{colors.neutral-muted}"
    rounded: "{rounded.pill}"
    padding: "0.25rem 0.65rem"
  tab-active:
    backgroundColor: "{colors.brand-interactive-dim}"
    textColor: "{colors.brand-interactive}"
    rounded: "{rounded.sm}"
    padding: "0.45rem 0.85rem"
---

# Design System: TUESDAY

## 1. Overview

**Creative North Star: "The Air-Gap Ops Room"**

This is the floor of a real security operations center at 3 a.m.: focused, quiet, every panel given a job, and nothing on screen that isn't working. TUESDAY is a defense instrument, not marketing theater. The atmosphere is a deep, near-black void with sparse signal lights — each glow carries a status meaning, and anything that doesn't carry status has been refused entry to the interface.

The system serves two faces of the same instruments. **Sentinel** (the defense console at 8090) is the calm command deck: emerald as the breathing "all clear," cyan for live data channels, purple for cognition. **RedTeam** (the adversary suite at 8095) shifts the room toward crimson and amber — the drills, but on the same hardware. The shared DNA keeps both apps recognizable as TUESDAY from across a room; the accent shift tells you which side of the glass you're on.

This system explicitly rejects the SaaS-purple admin dashboard, the cluttered hacker-movie terminal where nothing is scannable, and glow-on-glow illegibility. Verdicts are never the story alone — the evidence chain behind them is always legible. Atmosphere earns its place; every haze, pulse, and glow is either a status signal or focus feedback.

**Key Characteristics:**
- Deep void backgrounds with sparse, meaning-carrying signal color.
- Hairline borders + inner highlights establish depth; ambient shadow is reserved for floating layers.
- Machine-graded monospace (JetBrains Mono) for all telemetry, IOCs, and timestamps.
- Calm, clipped, operational voice — uppercase labels are data labels, not marketing kickers.
- Status-by-hue with paired text labels (never hue alone), respecting reduced motion.

## 2. Colors: The Signal Palette

Six signals, one job each. Dark neutrals recede; the signals are read off the room like instrument lights.

### Primary
- **Signal Emerald** (#00E599): Defended. Contained. Operational "all clear." The Sentinel identity color — defensive status, success verdicts, the safe-state banner, active telemetry values.
- **Signal Emerald Dim** (#0C211A): Emerald at rest — tinted button/pill backgrounds so signal text reads on surface.

### Secondary
- **Telemetry Cyan** (#38BDF8): Data in motion. Active tab, interactive affordances, event sources, focus rings. The color of the live stream.
- **Telemetry Cyan Dim** (#0D1F2C): Cyan tint for active tabs and hover surfaces.

### Tertiary
- **Thought Purple** (#A78BFA): Cognition — agent reasoning, ACH traces, episodic memory, the critic's reflection. Reserved for "the machine is thinking," never for layout decoration.
- **Thought Purple Dim** (#1A1633): Purple tint for badge counts and cognitive panels.

### Semantic
- **Compromise Crimson** (#F43F5E): Hostile. Detected. Critical. The highest-cost signal: hostile banner, detected MITRE cards, kill/terminate actions, RedTeam's identity accent.
- **Attention Amber** (#F59E0B): Pending. Human-approval queue, warnings, review gates.

### Neutral
- **Void Black** (#06080D): The room itself — body background.
- **Ops Surface** (#0B0E17): Subtle elevated panels, navbar, telemetry wells.
- **Card Surface** (#0D111A): Cards, modal, detail views.
- **Ink** (#F8FAFC): Primary text and headings.
- **Muted Ink** (#94A3B8): Body copy, secondary text.
- **Dim Ink** (#7C8DB0): Micro-meta only — timestamps, empty states, table headers.
- **Hairline** (#1C1F27) / **Hairline Strong** (#21242C): 1px structure lines — borders, dividers, tab separators.

**The Signal Rule.** Signal colors are status first, decoration never. Emerald means defended, cyan means data, purple means cognition, crimson means hostile, amber means pending. Recoloring an element for visual balance is forbidden; if an element has no status to carry, it is neutral.

**The Rarity Rule.** Compromise Crimson is expensive. It is reserved for genuinely hostile states — the hostile banner, detected MITRE cards, kill actions. A red that is merely emphatic is off-brand noise.

**The Split-Room Rule.** Sentinel leads with emerald; RedTeam leads with crimson. Cross-reuse is deliberate, never default — the two apps must be distinguishable at a glance.

## 3. Typography

**Display Font:** Plus Jakarta Sans (with -apple-system, Segoe UI, Roboto, sans-serif)
**Body Font:** Plus Jakarta Sans (same stack)
**Label/Mono Font:** JetBrains Mono (monospace)

**Character:** A measured grotesque for reading paired with a machine-graded monospace for instrumentation. The sans is confident and quiet; the mono is where the console does its talking — every number, IOC, timestamp, and terminal line is mono, so data reads as data.

### Hierarchy
- **Display** (800, clamp(1.5rem, 3vw, 2.25rem), 1.1, -0.02em): Brand lockup, major page titles (Digital Twin header, banner headlines).
- **Headline** (700, 1.05rem, 1.3): Threat banner titles, panel-level titles.
- **Title** (700, 0.8rem, 1.4, +0.03em): Card headers ("MITRE ATT&CK MATRIX", "HOST EDR & WATCHDOG").
- **Body** (400, 0.82rem, 1.5): Event descriptions, alert detail, help text. Cap 65–75ch.
- **Label** (600, 0.68rem, 1.4, +0.06em, uppercase): Telemetry labels, table column headers, tab labels, badge text.
- **Mono** (JetBrains Mono, 500–600, 0.68–0.84rem, 1.5): Telemetry values, timestamps, IOCs, terminal lines, socket/proc tables.

**The Instrument Label Rule.** Uppercase micro-labels are data labels: 0.6–0.68rem, tracking ≥0.04em, never used for prose. They name what the number behind them is — they are not decoration and not marketing kickers.

**The Bright-Line Rule.** Body copy is Ink or Muted Ink (#94A3B8 or brighter) on surface. Dim Ink (#7C8DB0) is micro-meta only: timestamps, table headers, empty states. Glow text is reserved for large numerals and single status words — never for paragraphs.

## 4. Elevation

Depth is tonal, not ambient. Surfaces are separated by hairlines and an inner top highlight; they read as milled hardware sitting in the void, not stacked panels floating on shadows. The one wide ambient shadow is reserved for floating layers — modal, twin node overlay.

### Shadow Vocabulary
- **Hairline** (`1px solid rgba(255,255,255,0.07)`): default surface separation — cards, tables, wells.
- **Inner Highlight** (`inset 0 1px 0 rgba(255,255,255,0.07), inset 0 0 0 1px rgba(255,255,255,0.02)`): resting tactile depth on cards, inputs, metric blocks.
- **Ambient Float** (`0 16px 36px -10px rgba(0,0,0,0.65)`): modal, twin node overlay, executive report.
- **Hover Lift** (`0 0 0 1px rgba(56,189,248,0.22)` — a crisp signal ring on the edge): interactive surfaces just under the cursor; the border shifts to the signal, no ambient blur.

**The No-Ghost Rule.** A card at rest is either hairline-plus-highlight OR ambient float, never both. A fully bordered card floating on a 36px-blur shadow reads as a 2014-ghost; if you can see it alongside a real UI and it looks like a drop shadow screenshot, the blur is too big and the border shouldn't be there. Reserve the big shadow for what genuinely floats.

## 5. Components

Controls are machined and tactile — they feel like hardware switches, with crisp focus glows and confident state changes.

### Buttons
- **Shape:** Gently curved, not rounded (6px radius).
- **Primary:** Tinted signal surface with solid signal text (Emerald above base-dimming on Sentinel, Crimson for destructive actions and on RedTeam). Padding 0.45rem 0.85rem.
- **Hover / Focus:** On hover the tint deepens, the border becomes the solid signal color, and a tight signal glow appears (≤12px). Press scales down 0.98. Focus uses the signal-border + glow, never outline-offset default.
- **Ghost / Outline:** Subtle white-on-void surface (3% white) with hairline border. Hover promotes to cyan text + cyan tint.
- **Solid Hostile CTA** (RedTeam INJECT ATTACK): Hostile Machined Fill (`#BE123C`) with Ink text; hover lifts to `#E11D48`. Reserved for the single loudest offensive action per surface.

### Chips / Pills
- **Style:** Full pill (999px). Tinted signal background, signal text, 0.3-alpha signal border, 0.65–0.68rem, 600, +0.03em tracking.
- **State:** Signal color carries the status (`.green`, `.red`, `.amber`). Pills are read as status tags, not decorative labels.

### Cards / Containers
- **Corner Style:** Moderate (14px).
- **Background:** Card Surface with backdrop blur over the void.
- **Shadow Strategy:** Hairline + inner highlight at rest (see Elevation — no ghost).
- **Border:** Hairline 1px.
- **Internal Padding:** 1.15rem; headers get a bottom hairline on a near-transparent gradient strip.
- **Hover:** Border warms to cyan (border-card-hover), no translation upward.

### Inputs / Fields
- **Style:** Near-void fill, hairline border, 6px radius, monospace text (IOCs and filters are data).
- **Focus:** Border snaps to cyan, plus a 2px soft cyan ring (`0 0 0 2px rgba(56,189,248,0.2)`).

### Navigation
- **Navbar:** 64px sticky glass rail (85% void, 20px blur), hairline bottom. Brand signal emerald lockup on the left; telemetry well in the center; header actions on the right.
- **Tabs:** Flat text buttons in a hairline rail. Active = cyan tint + cyan hairline border + inner top highlight. Live-count badges ride beside tab labels.

### Tables (Signature)
Host EDR socket tables, process tables, firewall rules. Monospace 0.78rem, uppercase micro headers on near-void, hairline rows, centered mono numerals. Suspicious rows are tinted Crimson and flagged with an explicit text label — never hue alone. Hover lifts a row with a faint white wash.

### Threat Banner (Signature)
The single most important component on the Incidents surface. Three states: **Idle** (emerald tint, pulsing status light, "SYSTEM STATUS: ACTIVE DEFENSE WATCHDOG ENFORCED"), **Hostile** (crimson tint and glow, breathing border pulse 1.8s, icon shake, threat title in crimson glow), **Contained** (emerald glow, "CONTAINED" title). Metrics render as stacked mono numerals in dark metric blocks. All pulses degrade to static at `prefers-reduced-motion`.

## 6. Do's and Don'ts

### Do:
- **Do** establish depth with hairline borders and inner highlights; reserve the wide ambient shadow for modal, twin overlay, and hover.
- **Do** use the signals by their semantic job: Emerald defended, Cyan data, Purple cognition, Crimson hostile, Amber pending.
- **Do** render every telemetry value, IOC, timestamp, and table cell in JetBrains Mono.
- **Do** use uppercase labels only as data labels (0.6–0.68rem, tracking ≥0.04em) that name the value below them.
- **Do** keep body and UI text at WCAG AA: 4.5:1 for body (Ink / Muted Ink on surface), 3:1 for large text; treat Dim Ink (#7C8DB0) as micro-meta only.
- **Do** pair every red/green status with a text label so it never depends on hue alone.
- **Do** provide `prefers-reduced-motion` alternatives — pulses become static indicator dots, entries become crossfades.

### Don't:
- **Don't** make it a generic SaaS-purple admin dashboard — no soft rounded cards, no muted-gray-on-tinted-white. This is a defense instrument.
- **Don't** build cluttered "hacker movie" terminals where nothing is scannable. Density serves hierarchy, never theater.
- **Don't** use glow-on-glow text: no neon-on-tint that fails contrast. Glow is for large numerals and status words, not paragraphs.
- **Don't** render a stateless one-shot verdict — evidence, hypotheses, and critic confidence are always visible next to the verdict.
- **Don't** present metrics as marketing numbers; they are live instrument readings.
- **Don't** use a colored border-left/right stripe (>1px) as an accent on cards, alerts, or list items — use tints, full borders, icons, or nothing.
- **Don't** use gradient text (`background-clip: text`), glassmorphism as a default, or decorative stripe/doodle backgrounds.
- **Don't** exceed 16px card radius (14 is the system) or 20px on modal; pill is for chips/tags only.
- **Don't** pair a full hairline border with a wide ambient shadow at rest (the ghost-card pattern).
- **Don't** clamp a heading smaller than its content needs — display wraps within the room, never overflows it.