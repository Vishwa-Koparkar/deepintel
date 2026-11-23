# DeepIntel product promo

## Brief and decisions

- **Purpose:** a short project overview for technical visitors reviewing the repository.
- **Audience:** security and software teams evaluating a local URL threat-analysis workflow.
- **Core features:** a dashboard verdict with reasons, the browser extension verdict, and an onion-link warning that keeps onion addresses out of the analysis API.
- **Format:** 24 seconds, 1920×1080, 30 fps, English, silent, with a matching WebVTT caption track.
- **Model/data:** no trained model artifacts were present during capture. The video uses a fixed synthetic response only. `secure-northstar.example` is under the reserved `.example` TLD, and the `.onion` address is a fabricated placeholder. Each captured screen says synthetic demo; no live model inference or user browsing data is shown.
- **Risk consistency:** dashboard score is `0.742` (within the UI's High range); popup confidence is `84.2%` (a separate fixture field).
- **Audio:** none. The browser embed can remain muted and captions can be enabled from the VTT track.

## Visual direction

Use the product's light analyst surfaces and navy extension header, with one restrained navy end card. Keep the real interface as the visual subject. Text, edges, and controls remain front-facing so their labels stay readable. Movement uses a small scale push, short slide, and 18-frame crossfades; no perspective tilt, decorative glow, or shake.

| Token | Product source | Promo use |
|---|---|---|
| Background | `#f0f4f8` | Intro and extension surfaces |
| Surface | `#ffffff` | Captured dashboard and warning cards |
| Border | `#d0dbe8`, `#e0e8f0` | Product edges and restrained framing |
| Text | `#1a2332` | Main copy |
| Muted | `#526985`, `#7a90a8` | Supporting copy and labels |
| Navy | `#0d1b3e` | Extension header and end card |
| Accent | `#1a4fa8`, `#a8c5e8` | Key phrases, rule, and end-card accent |
| High risk | `#c0392b`, `#e67e22` | Warning and risk evidence |
| Typography | DM Sans, JetBrains Mono, DM Serif Display in dashboard | DM Sans headlines; JetBrains Mono overlines; captured UI retains its own fonts |

Motion timing is deterministic: cubic-bezier `(0.2, 0.78, 0.24, 1)`, no overshoot, 18-frame exits/entries, and a held end card. The screen movement is deliberately flat: the product UI is information-dense, and a 3D angle would soften small text. This is a custom screenshot-led camera treatment, not a claim to reproduce a Gallery card.

## Feature-to-shot map and timeline

| Time | Source | One point |
|---|---|---|
| 0:00–0:03.3 | Native shield mark and wordmark | Read the link; see the risk |
| 0:02.7–0:12.1 | Real `dashboard.html` screenshot | Risk score with visible supporting signals |
| 0:11.5–0:17.9 | Real extension `popup.html` screenshot | Browser verdict, confidence, and reasons |
| 0:17.3–0:21.9 | Real extension `warning.html` screenshot | Onion links are kept off the analysis API |
| 0:21.3–0:24.0 | Brand end card | Repo URL and one tagline, held through the end |

Shots overlap by 18 frames for simple dissolves. The subtitle copy and times are in `website/assets/product/product-promo.vtt`.

## Capture and provenance

`scripts/demo-api.mjs` serves the production dashboard HTML and a deterministic fixture on `127.0.0.1:8000`. `scripts/capture.mjs` uses Brave and the real extension markup/styles. Dashboard analysis uses the local fixture endpoint; the popup screenshot calls the extension's existing `render()` function with that same fixture. It does not invoke the production analyzer, make a prediction, write feedback, or retain browsing data. The warning page runs its production warning script with the synthetic placeholder address.

Capture output is labeled **SYNTHETIC DEMO DATA** / **NO LIVE MODEL OUTPUT**. It is suitable for explaining the interface and is not evidence of a current model score.

## Rendered output

- `website/assets/product/dashboard.png`
- `website/assets/product/extension.png`
- `website/assets/product/warning.png`
- `website/assets/product/product-promo.mp4`
- `website/assets/product/product-poster.jpg`
- `website/assets/product/product-promo.vtt`
