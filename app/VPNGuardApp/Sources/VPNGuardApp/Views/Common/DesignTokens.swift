import SwiftUI
import AppKit

// MARK: - Layer 1: Primitive Tokens

/// Raw design primitives without semantic intent.
/// Do not reference directly in views; use `VGTokens` or `VGComponentTokens`.
public enum VGPrimitives {
    // MARK: Adaptive Color Helper
    fileprivate static func adaptive(dark: NSColor, light: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        })
    }

    // MARK: Color Primitives
    public enum Palette {
        // Neutrals (Alpha overlays for native vibrancy/surface layering)
        static let whiteAlpha045 = NSColor.white.withAlphaComponent(0.045)
        static let whiteAlpha060 = NSColor.white.withAlphaComponent(0.060)
        static let whiteAlpha080 = NSColor.white.withAlphaComponent(0.080)
        static let whiteAlpha090 = NSColor.white.withAlphaComponent(0.090)
        static let whiteAlpha100 = NSColor.white.withAlphaComponent(0.100)

        static let blackAlpha030 = NSColor.black.withAlphaComponent(0.030)
        static let blackAlpha045 = NSColor.black.withAlphaComponent(0.045)
        static let blackAlpha075 = NSColor.black.withAlphaComponent(0.075)
        static let blackAlpha080 = NSColor.black.withAlphaComponent(0.080)
        static let blackAlpha100 = NSColor.black.withAlphaComponent(0.100)

        // Emerald (Protection / Pass / Direct)
        static let emerald400 = NSColor(srgbRed: 0.20, green: 0.78, blue: 0.55, alpha: 1.0) // #33C78C (Dark mode text/icon)
        static let emerald600 = NSColor(srgbRed: 0.02, green: 0.59, blue: 0.41, alpha: 1.0) // #059669 (Fill for white text)
        static let emerald700 = NSColor(srgbRed: 0.02, green: 0.47, blue: 0.34, alpha: 1.0) // #047857 (Light mode text/icon >= 4.5:1)

        // Amber (Warning / Pause / Recovering)
        static let amber400 = NSColor(srgbRed: 0.94, green: 0.65, blue: 0.18, alpha: 1.0) // #F0A62E (Dark mode text/icon)
        static let amber700 = NSColor(srgbRed: 0.71, green: 0.33, blue: 0.04, alpha: 1.0) // #B45309 (Light mode text/icon >= 4.5:1)

        // Red (Danger / Block / Fail)
        static let red400 = NSColor(srgbRed: 0.90, green: 0.34, blue: 0.34, alpha: 1.0) // #E65757 (Dark mode text/icon)
        static let red700 = NSColor(srgbRed: 0.73, green: 0.11, blue: 0.11, alpha: 1.0) // #B91C1C (Light mode text/icon >= 4.5:1)

        // Blue (Primary Accent / VPN Route)
        static let blue500 = NSColor(srgbRed: 0.28, green: 0.52, blue: 0.96, alpha: 1.0) // #4785F5 (Dark mode)
        static let blue600 = NSColor(srgbRed: 0.15, green: 0.39, blue: 0.92, alpha: 1.0) // #2563EB (Light mode >= 4.5:1)

        // Indigo (Secondary Metric / Upload)
        static let indigo400 = NSColor(srgbRed: 0.51, green: 0.55, blue: 0.97, alpha: 1.0) // #818CF8 (Dark mode)
        static let indigo600 = NSColor(srgbRed: 0.31, green: 0.27, blue: 0.90, alpha: 1.0) // #4F46E5 (Light mode)
    }

    // MARK: Spacing Primitives (4pt base grid)
    public enum Space {
        public static let s0: CGFloat = 0
        public static let s2: CGFloat = 2
        public static let s4: CGFloat = 4
        public static let s6: CGFloat = 6
        public static let s8: CGFloat = 8
        public static let s10: CGFloat = 10
        public static let s12: CGFloat = 12
        public static let s14: CGFloat = 14
        public static let s16: CGFloat = 16
        public static let s20: CGFloat = 20
        public static let s24: CGFloat = 24
        public static let s32: CGFloat = 32
    }

    // MARK: Radius Primitives
    public enum Radius {
        public static let r4: CGFloat = 4
        public static let r6: CGFloat = 6
        public static let r8: CGFloat = 8
        public static let r12: CGFloat = 12
    }

    // MARK: Duration Primitives
    public enum Duration {
        public static let instant: Double = 0.0
        public static let fast: Double = 0.15
        public static let normal: Double = 0.20
        public static let slow: Double = 0.30
    }
}

// MARK: - Layer 2: Semantic Tokens

/// Purpose-based design tokens calibrated for macOS Dark & Light Aqua,
/// WCAG AA contrast, Dynamic Type, and Reduced Motion.
public enum VGTokens {
    // MARK: Colors (Adaptive)
    public enum Colors {
        // Window & Surfaces
        public static let backgroundContent = Color(nsColor: .windowBackgroundColor)
        public static let backgroundElevated = Color(nsColor: .controlBackgroundColor)

        public static let surfaceLevel1 = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.whiteAlpha045,
            light: VGPrimitives.Palette.blackAlpha030
        )
        public static let surfaceLevel2 = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.whiteAlpha060,
            light: VGPrimitives.Palette.blackAlpha045
        )
        public static let surfaceHover = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.whiteAlpha090,
            light: VGPrimitives.Palette.blackAlpha075
        )
        public static let sidebarSelection = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.whiteAlpha100,
            light: VGPrimitives.Palette.blackAlpha080
        )

        // Borders & Dividers
        public static let borderSubtle = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.whiteAlpha080,
            light: VGPrimitives.Palette.blackAlpha100
        )
        public static let divider = Color(nsColor: .separatorColor)

        // Typography
        public static let textPrimary = Color(nsColor: .labelColor)
        public static let textSecondary = Color(nsColor: .secondaryLabelColor)
        public static let textTertiary = Color(nsColor: .tertiaryLabelColor)
        public static let textOnAccent = Color.white

        // Semantic Accents & Statuses
        public static let accentPrimary = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.blue500,
            light: VGPrimitives.Palette.blue600
        )
        public static let accentSecondary = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.indigo400,
            light: VGPrimitives.Palette.indigo600
        )

        /// Foreground-safe emerald for text, icons, and badges in both Light & Dark mode.
        public static let statusProtected = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.emerald400,
            light: VGPrimitives.Palette.emerald700
        )
        /// High-contrast emerald fill for buttons with white foreground text (>= 5.4:1 in both themes).
        public static let statusProtectedFill = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.emerald700,
            light: VGPrimitives.Palette.emerald700
        )
        public static let statusWarning = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.amber400,
            light: VGPrimitives.Palette.amber700
        )
        public static let statusDanger = VGPrimitives.adaptive(
            dark: VGPrimitives.Palette.red400,
            light: VGPrimitives.Palette.red700
        )
    }

    // MARK: Typography Scale (Dynamic Type compatible)
    public enum Typography {
        public static let pageTitle: Font = .title2.weight(.semibold)
        public static let sheetTitle: Font = .title3.weight(.semibold)
        public static let sectionTitle: Font = .headline
        public static let cardTitle: Font = .subheadline.weight(.semibold)

        public static let body: Font = .callout
        public static let bodyEmphasis: Font = .callout.weight(.medium)

        public static let caption: Font = .caption
        public static let captionEmphasis: Font = .caption.weight(.medium)
        public static let badge: Font = .caption2.weight(.semibold)

        public static let metricHero: Font = .system(.title2, design: .rounded, weight: .semibold)
        public static let monoBody: Font = .system(.callout, design: .monospaced)
        public static let monoCaption: Font = .system(.caption, design: .monospaced)
    }

    // MARK: Spacing
    public enum Spacing {
        public static let pagePadding: CGFloat = VGPrimitives.Space.s24
        public static let sheetPadding: CGFloat = VGPrimitives.Space.s20
        public static let sectionGap: CGFloat = VGPrimitives.Space.s20
        public static let cardPadding: CGFloat = VGPrimitives.Space.s16
        public static let cardPaddingCompact: CGFloat = VGPrimitives.Space.s12
        public static let gridGap: CGFloat = VGPrimitives.Space.s12
        public static let inlineGap: CGFloat = VGPrimitives.Space.s8
        public static let microGap: CGFloat = VGPrimitives.Space.s4
    }

    // MARK: Corner Radii
    public enum Radius {
        public static let card: CGFloat = VGPrimitives.Radius.r12
        public static let control: CGFloat = VGPrimitives.Radius.r8
        public static let badge: CGFloat = VGPrimitives.Radius.r6
        public static let mini: CGFloat = VGPrimitives.Radius.r4
    }

    // MARK: Motion (Accessibility-aware)
    public enum Motion {
        public static func snappy(reduceMotion: Bool) -> Animation? {
            reduceMotion ? nil : .snappy(duration: VGPrimitives.Duration.normal)
        }

        public static func hover(reduceMotion: Bool) -> Animation? {
            reduceMotion ? nil : .easeOut(duration: VGPrimitives.Duration.fast)
        }

        public static func toastTransition(reduceMotion: Bool) -> AnyTransition {
            reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity)
        }
    }
}

// MARK: - Layer 3: Component Tokens

/// Component-specific token bindings referencing `VGTokens`.
public enum VGComponentTokens {
    public enum Card {
        public static let background: Color = VGTokens.Colors.surfaceLevel1
        public static let border: Color = VGTokens.Colors.borderSubtle
        public static let borderWidth: CGFloat = 0.75
        public static let accentBorderWidth: CGFloat = 1.0
        public static let cornerRadius: CGFloat = VGTokens.Radius.card
        public static let padding: CGFloat = VGTokens.Spacing.cardPadding
        public static let paddingCompact: CGFloat = VGTokens.Spacing.cardPaddingCompact
    }

    public enum Badge {
        public static let cornerRadius: CGFloat = VGTokens.Radius.badge
        public static let horizontalPadding: CGFloat = 7
        public static let verticalPadding: CGFloat = 3
        public static let dotSize: CGFloat = 6
        public static let fillOpacity: Double = 0.14
        public static let borderOpacity: Double = 0.25
    }

    public enum Button {
        public static let cornerRadius: CGFloat = VGTokens.Radius.control
        public static let minIconHitTarget: CGFloat = 28
    }

    public enum Row {
        public static let horizontalPadding: CGFloat = VGPrimitives.Space.s12
        public static let verticalPadding: CGFloat = VGPrimitives.Space.s8
        public static let cornerRadius: CGFloat = VGTokens.Radius.control
    }

    public enum Popover {
        public static let width: CGFloat = 356
        public static let padding: CGFloat = VGPrimitives.Space.s14
    }
}
