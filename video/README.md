# Product promo source

The 24-second silent MP4 is rendered from the product's real dashboard and extension screens. Local fixture data is visibly marked synthetic; it does not make a live inference call.

On this project machine, render from the repository root with:

```sh
cd video
npm ci
npm run capture
npm run render
npm run poster
```

Capture requires the local Brave Browser app and an unused port 8000. The fixture server only answers requests made during capture, does not use the project API or model files, and does not store feedback. `npm run capture` recreates the three PNG captures and copies render textures under `video/public/textures/`. `npm run render` writes `website/assets/product/product-promo.mp4`; `npm run poster` extracts the dashboard scene as `product-poster.jpg`. The VTT file is maintained alongside the edit.

`DESIGN_SPEC.md` records the product brief, visual tokens, demo-data boundary, and timeline. The local DM Sans and JetBrains Mono files in `public/fonts/` retain their upstream OFL licenses.
