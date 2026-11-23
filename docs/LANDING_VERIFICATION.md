# Landing-page verification

The current revision adds real dashboard/extension captures and a rendered product film, removes single-person attribution and profile links, and integrates the updated README and public-demo deployment plan.

## Functional checks

- `node website/app.test.cjs` tests all walkthrough selections, exclusive button state, repository-only attribution, and the presence of referenced local media/assets.
- `node scripts/test_dashboard_origin.cjs` tests hosted API origins, local API and standalone previews, public read-only mode, local compatibility, and offline feedback gating.
- `node --test browser-extension/hops.test.js browser-extension/onion.test.js browser-extension/cookies.test.js` covers the existing extension helpers.
- Public-demo gateway tests and container checks are recorded in `deploy/` and the hosting guide.
- Video sources, fixture provenance, timeline, captures and render instructions are recorded in `video/`.

The media uses the actual product frontends with explicitly fixed demonstration data. It does not claim measured live inference, production adoption, or individual authorship.

## Limits

The earlier strict Taste design gate remained open with 55 findings. Its fixed-screen-height, grid and nested-UI conventions did not pass; this revision does not claim to clear that gate. The engine source link now has an explicit high-contrast keyboard focus style. Real-browser interaction, keyboard focus, reduced-motion, and 320–1440px overflow checks passed. The independent media reviewer inspected actual frames at 6, 14, 20, and 23 seconds; repo attribution, synthetic-data disclosure, score consistency, and final typography passed targeted review.

No remote GitHub or backend deployment is implied by local files. A fresh model was trained from committed splits; native artifacts are in ignored models/. The ONNX proof includes an exported model. Public backend deployment still requires staging trusted artifacts. Browser configuration remains local-first until a real hosted backend URL is selected.

The real-model public gateway integration check passed readiness, dashboard/config routes, blocked feedback, input validation/body cap, inference, and shared rate limiting. Docker memory-cap testing is not complete because the daemon is unavailable. Workbench frame parity is not complete; the actual MP4 was independently inspected. Browser feature/model parity results are in ../browser-prototype/browser-results.json; full detector/explanation parity remains unimplemented.
