# Kāhea identity system

The crest turns Kāhea's product contract into geometry: an intent enters at the open seam, an authority boundary resolves it, and a precise response returns. The two black fields are deliberately unequal—the larger call and the smaller response—while the copper aperture marks the invocation itself.

## Master artwork

- `kahea-primary.svg`: preferred vertical crest and outlined wordmark.
- `kahea-primary-mono.svg`: one-color production fallback.
- `kahea-crest.svg`: standalone mark for icons, avatars, and compact placements.
- `kahea-crest-mono.svg`: one-color standalone mark.

The SVG wordmark is outlined. It has no runtime font dependency and the macron is part of the original glyph geometry.

## Construction

The crest uses a 512 × 512 construction grid with a shared axis at x = 256.

| Element | Measurement |
|---|---:|
| Outer ring | radius 220, stroke 22 |
| Primary call field | radii 184 / 112 |
| Response field | radii 112 / 70 |
| Central seam | 16 units |
| Minimum clear space | 64 units on every side |

Do not close, rotate, widen, or decorate the seam. It is the mark's semantic spine.

## Color

| Token | Hex | Purpose |
|---|---|---|
| Invocation ink | `#171716` | Crest structure and wordmark |
| Signal copper | `#A9452E` | Central invocation aperture only |
| Protocol ivory | `#F6F1E8` | Preferred presentation field |

The master SVGs have transparent backgrounds. On dark fields, use the monochrome mark in white; do not invert the copper independently.

## Minimum size

- Crest: 20 px digital, 7 mm print.
- Monochrome crest: 14 px digital, 5 mm print.
- Primary lockup: 180 px wide digital, 40 mm print.

Below 20 px, use the monochrome crest. Do not use the primary lockup where the macron cannot remain clearly visible.

## Usage constraints

- Preserve the spelling **Kāhea** in prose and **KĀHEA** in the display wordmark.
- Preserve the macron; it is never optional.
- Keep the descriptor “The Agentic Invocation Kernel” separate from the core mark at small sizes.
- Do not add pseudo-Hawaiian ornament, sacred imagery, gradients, shadows, or enclosing shields.
- Do not recreate the wordmark as live text.
