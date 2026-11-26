---
trigger: glob
globs:
  - "app/VPNGuardApp/**/*.swift"
---

# VPNGuardApp Design System Rules (macOS 14+ SwiftUI / AppKit)

These rules govern all UI work in `app/VPNGuardApp/` and must be followed for every new screen, sheet, popover, or component.

## 1. Single Source of Truth: `VGTokens` & `VGComponentTokens`
- **Always** use `VGTokens` and `VGComponentTokens` from `Views/Common/DesignTokens.swift` for colors, typography, spacing, corner radii, and motion.
- **Never** hardcode raw `Color(red:green:blue:)`, `.white`, `.black`, `.orange`, `.green`, `.indigo`, `.font(.system(size: ...))`, or arbitrary spacing/radius literals in views.
- **Never** extend or add new tokens to `VGTheme` (`Views/Common/DesignSystem.swift`). `VGTheme` is a legacy compatibility proxy only; new code must reference `VGTokens` / `VGComponentTokens` directly.

## 2. Adaptive Light & Dark Aqua + WCAG AA Contrast
- All custom colors must adapt to both `.darkAqua` and `.aqua` via `VGTokens.Colors`.
- Maintain **≥ 4.5:1** contrast for normal text and **≥ 3:1** for icons/UI boundaries in both appearances.
- For white text (`VGTokens.Colors.textOnAccent`) on green protection CTAs (e.g., `.borderedProminent`), always use `VGTokens.Colors.statusProtectedFill` (≥ 5.4:1), never `statusProtected` (which is calibrated for foreground text/icons).
- Never dim disabled rows with low `.opacity(...)` if it drops text below readable contrast; prefer `.tertiary` foreground styles or explicit status badges.

## 3. Native macOS Patterns, Keyboard Focus & Hit Targets
- **Sidebar Navigation:** Use native `List(selection:)` with `.listStyle(.sidebar)`. Do not add custom `listRowBackground` or override selected foreground styles in ways that conflict with macOS's native selection highlight.
- **Buttons & Focus Rings:** Never use `.buttonStyle(.plain)` on interactive buttons where it strips keyboard focus rings and pressed feedback.
  - Primary CTAs: `.buttonStyle(.borderedProminent)` with `.tint(VGTokens.Colors.accentPrimary)` or `statusProtectedFill`.
  - Secondary / Toolbar actions: `.buttonStyle(.bordered)` or `.buttonStyle(VGSurfaceButtonStyle())`.
  - Icon-only buttons: `.buttonStyle(VGIconButtonStyle())` (enforces `VGComponentTokens.Button.minIconHitTarget` = `28pt`, hover state, and visible `@FocusState` ring).
  - Compact inline pill toggles: `.buttonStyle(.borderless)` or focus-aware styles.
- **Interactive Rows:** Never rely solely on `.onTapGesture` for row actions; provide focusable `Button` controls and `.accessibilityAction(...)`.

## 4. Accessibility & Reduced Motion
- **Dynamic Type:** Use `VGTokens.Typography` semantic font styles (`pageTitle`, `sheetTitle`, `sectionTitle`, `cardTitle`, `body`, `bodyEmphasis`, `caption`, `captionEmphasis`, `badge`, `metricHero`, `monoBody`, `monoCaption`).
- **Reduced Motion:** Read `@Environment(\.accessibilityReduceMotion)` and pass it to `VGTokens.Motion.snappy(reduceMotion:)`, `hover(reduceMotion:)`, and `toastTransition(reduceMotion:)`.
- **VoiceOver:** Every icon-only button must have an explicit, context-rich `.accessibilityLabel(...)`. Purely decorative icons/dots must have `.accessibilityHidden(true)`.
- **No Emoji as Structural Icons:** Use SF Symbols or typographic codes (e.g., `RU`, `DE`) instead of country/UI emojis.

## 5. Unified States, Minimal Visual Noise & `820pt` Responsiveness
- **Loading / Empty / Error:** Always use `VGLoadingStateView`, `VGEmptyStateView`, and `VGErrorBanner` from `DesignSystem.swift` instead of ad-hoc spinners or inline error boxes.
- **Minimalism:** Group dense lists inside a single `VGCard(padding: 0)` with subtle `Divider()`s and `vgHoverRow(cornerRadius: 0)` instead of wrapping every row in a bordered box. Consolidate protocol/tag metadata into clean typographic lines rather than clusters of neutral pill badges.
- **Minimum Window Width (`820pt`):** Horizontal toolbars, filter bars, and toggle grids must use `ViewThatFits(in: .horizontal)` or `LazyVGrid(columns: [GridItem(.adaptive(minimum: ...))])` so labels never clip or truncate at `820pt`.
- **Overlay Clearance:** Floating `ToastView` overlays must remain offset above `VGUnsavedChangesBar` whenever `vm.hasUnappliedChanges` is `true`.
