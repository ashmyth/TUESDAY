# Product

## Register

product

## Users

- **Tier 1/2 SOC Analysts (Alex):** Drowning in alert fatigue — thousands of events daily. They need an autonomous assistant that triages routine incidents in seconds, shows transparent reasoning, and escalates only high-risk edge cases. Their context: high pressure, limited time per alert, tuned to spot pattern breaks fast.
- **CISOs / Compliance Leads (Elena):** Demand absolute data sovereignty and defensible audit trails. They need proof that zero telemetry leaves the endpoint and automated regulatory reporting (GDPR Art 33/34, PCI-DSS). Their context: board reviews, audits, "show me the evidence."
- **Detection Engineers / Purple Teamers (Marcus):** Need to validate detection rules and containment without risking live systems, using on-host canary drills to measure real MTTD/MTTR. Their context: iterating on rules, comparing hypothesis vs outcome.

## Product Purpose

TUESDAY is an autonomous, on-device, air-gapped SOC + host EDR platform. A swarm of eight specialist agents investigates every alert with competing hypotheses (H1 hostile / H2 benign), an adversarial critic challenges the consensus, and only then does an enforcer contain the threat against real OS surfaces (netsh / iptables, registry, process trees). Everything runs 100% locally on SLMs via Ollama with zero network egress and an instantaneous deterministic fallback when the model is unavailable.

Success looks like: routine incidents resolved in seconds with a legible reasoning chain, zero external bytes leaked, every autonomous action reversible in one click, and a purple-team simulator that empirically provokes and validates the defense. The interface must make this cognitive rigor visible — the verdict is worthless to this audience without the evidence trail behind it.

## Brand Personality

Disciplined · Tactical · Precise. A calm, authoritative command console — think air-gap ops room, not cyberpunk cosplay. Confident enough to show its reasoning process in full, never theatrical, never panicked. The atmosphere (deep black, glowing signal colors) is the brand's restraint made visible: every glow carries threat or status meaning.

Voice: clipped, operational, factual. Labels like "CONTAINED" and "PENDING APPROVAL" are not decorative — they are the working vocabulary of the console.

## Anti-references

- **Generic SaaS admin dashboards** (Tailwind-purple, soft rounded cards, muted-gray-on-tinted-white). TUESDAY is a defense instrument; it must never read as a generic B2B panel.
- **Cluttered "hacker movie" terminals** — dense green-on-black noise where nothing is scannable. Atmosphere without scannability is theater; operators triage under duress and need hierarchy at a glance.
- **Glow-on-glow illegibility.** Neon text on dark tints that fails WCAG AA ruins the entire audit story. Signal color must always sit on adequate contrast.
- **Stateless one-shot AI wrappers** — a single evaluation with no hypothesis comparison, no memory, no critic. The UI must never appear to overclaim certainty; evidence and confidence adjustments are shown, not hidden.
- **The hero-metric SaaS cliché** — big glowing metrics with no grounding. TUESDAY metrics are live telemetry, and the UI should present them as instrument readings, not marketing numbers.

## Design Principles

1. **Evidence before verdict.** Every verdict surface must be traceable to its reasoning chain — ACH hypotheses, critic challenge, recalled memory. The console shows how, not just what.
2. **Stealth, not spectacle.** Atmosphere serves legibility. If a glow, blur, or animation doesn't carry status or meaning, it's noise. Density and scannability win over decoration.
3. **Guard the operator's attention.** Alert fatigue is the adversary of the analyst. Visual hierarchies must make severity and state unmistakable before any secondary detail.
4. **Everything reversible, everything visible.** Every autonomous action is indexed with a one-click rollback; the interface never creates a state it can't unwind, and never hides the audit trail.
5. **Air-gapped by principle, honest by design.** The tool is local-first and privacy-preserving; the UI behaves accordingly — no flourishes that imply a cloud AI backend, no telemetry theater.

## Accessibility & Inclusion

- **Target:** WCAG AA-compliant contrast for UI text and body copy (≥4.5:1; large text ≥3:1), including placeholder and dynamic state colors. Signal colors must meet the bar on their backgrounds, not just raw hue.
- **Reduced motion:** every animation needs a `@media (prefers-reduced-motion: reduce)` alternative — generally an instant or cross-fade transition. Pulsing/banner animations are the first to degrade.
- **Color-blind consideration:** never encode status by hue alone (red/green). Pair with icons, text labels, and patterns (e.g., threat/contained states always carry a text label).
- **Color names should carry semantics, not decimals:** statuses should be readable as words to screen readers, not just as glowing pills.