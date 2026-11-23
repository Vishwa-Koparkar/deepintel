# Deployment plan

## Publish the showcase now

The landing page is static HTML/CSS/JavaScript with local product screenshots, a captioned promo, and an illustrative evidence walkthrough. It does not perform live URL inference.

1. A repository admin selects **Settings → Pages → Build and deployment → Source → GitHub Actions**.
2. Run **Deploy landing page** from Actions after enabling Pages. Later changes to `website/` on `main` deploy automatically.
3. Verify the URL returned by the deployment. The expected project URL is `https://vishwa-koparkar.github.io/deepintel/`.
4. Add the verified URL to the repository About field, resume and LinkedIn Featured. Update the page's canonical/social URLs if a different hostname is used.

The workflow publishes only the landing-page files and assets. It does not upload datasets, personal corrections, native model artifacts, or the browser experiment.

[GitHub Pages publishing instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)

## Recommended next step: on-device inference

A local browser feasibility experiment ran the trained XGBoost model in ONNX Runtime Web's WASM backend. Across 6,556 current test URLs, 131,120 float32 feature values matched Python and model labels had zero changes; maximum class probability error was below 0.000001. The ONNX model was 2.05 MB uncompressed (283 KB gzip). Runtime assets add approximately 15 MB uncompressed; the WASM alone compresses to 3.81 MB. These are local prototype measurements, not a deployed product guarantee. The older committed full-system evaluation covers 6,555 URLs and remains separate.

Before publishing a browser detector:

- Port heuristics, score fusion, threat-list snapshots, trusted-domain/lookalike checks, risk levels, reasons, decision trace and equivalent feature contributions. Model probabilities alone are not the full verdict.
- Compare the complete browser pipeline against a fresh Python reference on identical URLs, including malformed inputs, lookalikes, blocklist hits and trailing-slash cases. Require no final-label/risk/deciding-layer regressions.
- Test Chrome, Safari and Firefox, mobile startup/memory, and initial versus cached downloads. Keep inference off the UI thread if needed.
- Publish versioned model and lookup snapshots with a manifest. Training and feed collection remain offline release jobs; personal corrections can be device-local. Global feedback/retraining needs a separate authenticated service if desired.

After parity passes, package the model and required WASM files as same-origin static assets and deploy them through the same GitHub Pages workflow. This removes the need for an inference server; static hosting is still needed to deliver the site and model. The Chrome extension will need its own local-runtime packaging and permissions review.

[ONNX Runtime Web deployment guidance](https://onnxruntime.ai/docs/tutorials/web/deploy.html)

## Hosted fallback

If an API is still needed, use a read-only Python service with trained artifacts packaged in advance. Disable public feedback routes, validate request size/schemes, add rate limits, preload the model for readiness, and retain the Python detector's explanations.

Render offers a no-cost web-service plan, but only 512 MB RAM/0.1 CPU, idle sleep after 15 minutes, and ephemeral storage. Test the actual container under a 512 MB cap before choosing it; this resource fit has not been proven. A sleeping service is a poor first-click experience for resume visitors. Do not store personal corrections on its ephemeral filesystem.

Hugging Face Docker/Gradio CPU Spaces currently require a paid subscription to create, despite CPU Basic having no hourly hardware charge. Do not treat that option as universally free.

Provider facts checked against [Render's free-tier documentation](https://render.com/docs/free), [compute plans](https://render.com/docs/compute-plans), and [Hugging Face's Spaces policy](https://huggingface.co/docs/hub/en/spaces-overview).
