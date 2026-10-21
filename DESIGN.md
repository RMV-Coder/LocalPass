# Design System — LocalPass

The source of truth for every visual and interaction decision in the desktop /
mobile GUI (`apps/desktop`) and the browser extension (`apps/extension`). Read it
before changing UI. Deviations need a line in the Decisions Log.

## Product context

- **What this is:** a fully local, open-source password and secrets manager
  (1Password alternative) with a developer focus: `.env` sets, API keys, SSH
  keys, a CLI, and an MCP server so AI agents can *spend* secrets without
  receiving them.
- **Who it's for:** developers and privacy-minded people who will not put
  secrets in someone else's cloud.
- **Project type:** native-feeling desktop + mobile app (Tauri 2 + Svelte 5),
  hand-written CSS, strict CSP (no remote fonts, scripts or images).
- **The one thing to remember:** *quiet, solid, mine.* A precise instrument that
  belongs to the OS, with one satisfying moment: the lock turning.

## Aesthetic direction

- **Direction:** native instrument. It should look like it shipped with the OS:
  native title bar, native UI font, no glows, glass, gradients or decorative
  texture.
- **Decoration:** minimal. Hierarchy comes from surfaces and type, not boxes.
  Use spacing and hairline dividers; a bordered container only for a real
  object (dialog, device, code block).
- **Where personality lives (and only here):** the mark, the secret values (set
  in mono, given room), and the lock/unlock motion.

## Brand mark

- **Mark A, "Keyhole-L":** a keyhole whose slot kicks right into an L, cut from a
  rounded tile. Master geometry on a 100-unit grid lives in
  `apps/desktop/src/components/Mark.svelte` and `apps/desktop/brand/`.
- **Colours:** mark brass `#D4A24C`, mark ink `#1A1917`. The *app icon* is a
  brass tile with an ink keyhole; the *inverse* (ink tile, brass keyhole) is
  for small in-app lockups on light surfaces where a brass tile would shout.
- **Tile radius:** 23% of the edge (matches the macOS / iOS icon corner).
- **Never:** a letter "L" in a box, outlines of the mark, gradients on the
  mark, the mark recoloured outside brass/ink.
- **Wordmark:** "LocalPass" in the platform display font, 600 weight,
  -0.01em tracking. No custom lettering.

## Typography

- **UI / body:** the platform font, deliberately. `"Segoe UI Variable Text",
  "Segoe UI", system-ui, -apple-system, "SF Pro Text", Cantarell, "Noto Sans",
  Roboto, sans-serif`. Native text is what "built for Windows / macOS / Linux /
  Android" means; it is the one place we accept the system default.
- **Display (titles, wordmark):** the same family's display cut (`Segoe UI
  Variable Display`, `SF Pro Display`).
- **Secrets, values, code, fingerprints, TOTP:** **JetBrains Mono** (variable,
  OFL-1.1), bundled locally via `@fontsource-variable/jetbrains-mono`. Chosen
  for function: 0/O and l/1/I are unambiguous when a value is read aloud or
  typed by hand.
- **Scale (px):** 12 label · 13 secondary · 14 body · 16 mobile body · 20 title ·
  28 display · 28 mono TOTP. Line-height 1.5 body, 1.2 titles.
- **Rules:** labels are 12px muted sentence case (no uppercase eyebrows); values
  are 14px mono in full text colour. Numbers that update use `tabular-nums`.

## Colour

- **Approach:** restrained. Neutral graphite surfaces (no hue tint on greys),
  one accent, semantic colours only for meaning.
- **Accent (brass):** light `#8C6318` (text, icons, primary fill; white on it is
  5.4:1), dark `#E2B457` (fill with `#1F1606` text, 9.3:1). Used for: the primary
  action, the current selection, focus, the mark. Nothing else.
- **Selection tint:** light `#F3E9D2`, dark `#3A2F17`. Text on it stays `--text`.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg-app` | `#F3F2EE` | `#121211` | window, sidebar |
| `--bg-list` | `#FAF9F7` | `#171716` | item list pane |
| `--bg-content` | `#FFFFFF` | `#1C1C1A` | detail / tool pane, inputs |
| `--bg-elevated` | `#FFFFFF` | `#242422` | dialogs, menus, toasts |
| `--bg-hover` | `#EBE9E3` | `#2A2926` | row / button hover |
| `--border` | `#E4E2DB` | `#2D2C29` | hairlines |
| `--border-strong` | `#D1CEC5` | `#3A3935` | control outlines |
| `--text` | `#1B1A17` | `#EDEBE5` | primary text (17.4:1 / 14.3:1) |
| `--text-muted` | `#66635B` | `#A29F95` | labels, secondary (6.0:1 / 6.4:1) |
| `--text-faint` | `#8D8A80` | `#7D7A71` | timestamps, hints only (non-essential) |
| `--success` | `#2D7A46` | `#74D39A` | synced, copied, armed |
| `--warning` | `#B4460A` | `#FF9E5E` | behind, weak; always with an icon or word |
| `--danger` | `#B3261E` | `#FF8F87` | destructive, alarms |

- **Dark mode:** a full tonal redesign of the surfaces (not black + neon), the
  accent lifted for contrast, follows `prefers-color-scheme`.

## Spacing, shape, layout

- **Base unit:** 4px. Density: compact-comfortable (desktop rows 30–36px,
  touch targets ≥ 44px on mobile).
- **Radius:** 6px controls and rows, 10px dialogs and panels, 23% for the icon
  tile only. Pills (999px) only for compact status.
- **Desktop (≥ 1000px):** three panes, sidebar 216px · list 280px · content.
  Tool screens (Generator, Security, Devices, Developer, Settings) span both
  right panes; the item list shows only for a vault.
- **Compact desktop (720–999px):** the sidebar collapses to a 56px icon rail.
- **Mobile (< 720px):** one screen at a time, bottom tab bar with 4 tabs (Vault,
  Generator, Devices, More). Detail and forms push over the list with Back.
- **Nothing is cropped:** every text container has `min-width: 0` and either
  wraps (`overflow-wrap: anywhere` for values) or truncates with a tooltip;
  wide content (logs, code) scrolls inside its own box, never the page.

## Interaction rules

- **Click to copy:** a field row *is* the copy button. Hover (pointer) shows
  "Click to copy"; a click confirms in place ("Copied · clears in 30s") for
  ~1.6s. Keyboard: the row is focusable, Enter/Space copies.
- **Reveal:** an eye icon button on secret rows only (`aria-pressed`). Revealed
  values re-mask on item change, lock, and after 30s.
- **Destructive actions** live behind an overflow menu or a typed confirmation,
  never as a permanently visible red link.
- **Status is ambient:** the sidebar foot shows agent connection, sync freshness
  and the auto-lock countdown; a status line never needs a tab switch.
- **Copy:** say the verb and the object ("Unlock", "Copy password", "Sync now").
  Explanations go in Help or behind "How this works", not above the controls.

## Motion

- **Approach:** minimal-functional, plus one signature.
- **Signature, unlock:** the keyhole turns a quarter (−90°, 520ms,
  `cubic-bezier(0.65, 0, 0.35, 1)`), then the vault rises 10px and fades in
  (260ms ease-out). **Lock:** the vault drops away (160ms), the unlock screen
  returns with the keyhole turned, and it turns back (520ms).
- **Everything else:** 120–180ms colour/opacity fades. No bounce, no scale on
  hover, no entrance animations on lists.
- **Reduced motion:** instant swap, no turn.
- **Easing:** enter `cubic-bezier(0.2, 0, 0, 1)` · exit ease-in · turn
  `cubic-bezier(0.65, 0, 0.35, 1)`.

## Platform icon pipeline

`apps/desktop/brand/` holds the master SVGs; `npm run icons` (in
`apps/desktop`) renders them and runs `tauri icon` so every platform gets the
same mark:

- **Windows / Linux:** full-bleed rounded tile (`app-icon.png`, 1024px).
- **macOS (`icon.icns`):** the tile inset to Apple's 824/1024 grid.
- **Android:** the adaptive-icon safe zone holds the keyhole; the launcher mask
  (circle / squircle) cuts the brass background, never the glyph.
- **iOS:** full-bleed square on brass (the OS applies the corner).
- **Browser extension:** 16/32/48/128 PNGs from the same source.

## Decisions log

| Date | Decision | Rationale |
|---|---|---|
| 2026-10-21 | Initial system: native instrument, brass accent, Keyhole-L mark, JetBrains Mono for values | /design-consultation + /design-shotgun; user chose "quiet, solid, mine", mark A, brass |
| 2026-10-21 | Platform UI font instead of a bundled display face | User asked for an app that feels built for each OS |
