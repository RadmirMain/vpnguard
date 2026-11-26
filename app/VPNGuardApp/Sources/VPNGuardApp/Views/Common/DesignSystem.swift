import SwiftUI
import AppKit

// MARK: - Theme Tokens (Compatibility Proxy -> VGTokens)
/// Compatibility proxy over `VGTokens` so existing views automatically inherit
/// adaptive Light/Dark Aqua colors and unified spacing/radius tokens.
public enum VGTheme {
    // MARK: Adaptive Surfaces
    public static var backgroundContent: Color { VGTokens.Colors.backgroundContent }
    public static var surfaceLevel1: Color { VGTokens.Colors.surfaceLevel1 }
    public static var surfaceLevel2: Color { VGTokens.Colors.surfaceLevel2 }
    public static var surfaceHover: Color { VGTokens.Colors.surfaceHover }
    public static var sidebarSelection: Color { VGTokens.Colors.sidebarSelection }
    public static var borderSubtle: Color { VGTokens.Colors.borderSubtle }

    // MARK: Semantic Colors
    /// Muted emerald for active protection, PASS, Direct
    public static var statusProtected: Color { VGTokens.Colors.statusProtected }
    /// High-contrast emerald fill for buttons with white foreground text
    public static var statusProtectedFill: Color { VGTokens.Colors.statusProtectedFill }
    /// Amber for pauses, warnings, Touch ID prompts
    public static var statusWarning: Color { VGTokens.Colors.statusWarning }
    /// Muted red for disconnect, block, FAIL, delete
    public static var statusDanger: Color { VGTokens.Colors.statusDanger }
    /// Primary accent for primary CTAs and interactive controls
    public static var accentPrimary: Color { VGTokens.Colors.accentPrimary }

    // MARK: Radii
    public static var radiusCard: CGFloat { VGTokens.Radius.card }
    public static var radiusControl: CGFloat { VGTokens.Radius.control }
    public static var radiusBadge: CGFloat { VGTokens.Radius.badge }

    // MARK: Spacing
    public static var pagePadding: CGFloat { VGTokens.Spacing.pagePadding }
    public static var sheetPadding: CGFloat { VGTokens.Spacing.sheetPadding }
    public static var cardPadding: CGFloat { VGTokens.Spacing.cardPadding }
    public static var sectionSpacing: CGFloat { VGTokens.Spacing.sectionGap }
}

// MARK: - Formatters & Sanitizers
public enum VGFormatters {
    public static func formatPID(_ pid: Int?) -> String {
        guard let pid else { return "—" }
        return String(pid)
    }

    public static func formatProtocol(_ raw: String) -> String {
        switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "vless": return "VLESS"
        case "xhttp": return "XHTTP"
        case "tls": return "TLS"
        case "reality": return "Reality"
        case "doh": return "DoH"
        case "quic": return "QUIC"
        case "tcp": return "TCP"
        case "ws", "websocket": return "WS"
        case "grpc": return "gRPC"
        case "xtls-rprx-vision": return "Vision"
        case "": return "—"
        default: return raw.uppercased()
        }
    }

    public static func formatBytes(_ bytes: Int64) -> String {
        let b = max(0, bytes)
        if b < 1024 {
            return "\(b) Б"
        }
        let kb = Double(b) / 1024.0
        if kb < 1024.0 {
            return String(format: "%.1f КБ", kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f МБ", mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f ГБ", gb)
    }

    public static func formatSpeed(_ bytesPerSec: Int64) -> String {
        let b = max(0, bytesPerSec)
        if b == 0 {
            return "0 Б/с"
        }
        return "\(formatBytes(b))/с"
    }

    public static func stripANSI(_ text: String) -> String {
        text.replacingOccurrences(
            of: "\u{001B}\\[[0-9;]*[A-Za-z]",
            with: "",
            options: .regularExpression
        )
    }

    private static let isoFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let isoStandard: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    public static func formatLocalTimeFromISO(_ isoString: String) -> String {
        guard let date = isoFractional.date(from: isoString) ?? isoStandard.date(from: isoString) else {
            return isoString
        }
        return formatLocalTime(date)
    }

    private static let localTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "ru_RU")
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    public static func formatLocalTime(_ date: Date) -> String {
        localTimeFormatter.string(from: date)
    }

    public static func formatCountdown(until endDate: Date, now: Date = Date()) -> String? {
        let remaining = Int(ceil(endDate.timeIntervalSince(now)))
        guard remaining > 0 else { return nil }
        let mins = remaining / 60
        let secs = remaining % 60
        return String(format: "%02d:%02d", mins, secs)
    }

    /// Converts raw ANSI log text into clean AttributedString with semantic level highlighting
    public static func attributedLogs(from raw: String, searchQuery: String = "") -> AttributedString {
        let cleaned = stripANSI(raw)
        let lines = cleaned.components(separatedBy: .newlines)
        let trimmedQuery = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        var result = AttributedString()

        for (idx, line) in lines.enumerated() {
            var attrLine = AttributedString(line)
            attrLine.font = .system(size: 11.5, design: .monospaced)

            let upper = line.uppercased()
            if upper.contains("ERROR") || upper.contains("FATAL") || upper.contains("FAIL") {
                attrLine.foregroundColor = VGTheme.statusDanger
            } else if upper.contains("WARN") {
                attrLine.foregroundColor = VGTheme.statusWarning
            } else if upper.contains("DEBUG") {
                attrLine.foregroundColor = .secondary
            } else {
                attrLine.foregroundColor = .primary
            }

            // Highlight all search query matches on this line
            if !trimmedQuery.isEmpty {
                var searchStart = attrLine.startIndex
                while searchStart < attrLine.endIndex,
                      let range = attrLine[searchStart...].range(of: trimmedQuery, options: .caseInsensitive) {
                    attrLine[range].backgroundColor = VGTheme.statusWarning.opacity(0.28)
                    searchStart = range.upperBound
                }
            }

            result.append(attrLine)
            if idx < lines.count - 1 {
                result.append(AttributedString("\n"))
            }
        }
        return result
    }
}

/// Thread-safe in-memory cache for application icons and bundle existence checks.
public final class AppIconCache: @unchecked Sendable {
    public static let shared = AppIconCache()

    private let iconCache = NSCache<NSString, NSImage>()
    private let lock = NSLock()
    private var existsCache: [String: (exists: Bool, checkedAt: Date)] = [:]
    private let existsTTL: TimeInterval = 10.0

    private init() {
        iconCache.countLimit = 256
    }

    public func exists(_ path: String) -> Bool {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let now = Date()
        lock.lock()
        if let entry = existsCache[trimmed], now.timeIntervalSince(entry.checkedAt) < existsTTL {
            lock.unlock()
            return entry.exists
        }
        lock.unlock()

        let found = FileManager.default.fileExists(atPath: trimmed)
        lock.lock()
        existsCache[trimmed] = (found, now)
        lock.unlock()
        return found
    }

    public func icon(forAppPath path: String) -> NSImage? {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let key = trimmed as NSString
        if let cached = iconCache.object(forKey: key) {
            return cached
        }
        guard exists(trimmed) else { return nil }

        let image = NSWorkspace.shared.icon(forFile: trimmed)
        iconCache.setObject(image, forKey: key)
        return image
    }

    public func iconOrDefault(forAppPath path: String) -> NSImage {
        if let cached = icon(forAppPath: path) {
            return cached
        }
        let key = path as NSString
        if let cached = iconCache.object(forKey: key) {
            return cached
        }
        let image = NSWorkspace.shared.icon(forFile: path)
        iconCache.setObject(image, forKey: key)
        return image
    }
}

// MARK: - Reusable Components

public struct VGCard<Content: View>: View {
    let padding: CGFloat
    let accentBorder: Color?
    let content: Content

    public init(
        padding: CGFloat = VGComponentTokens.Card.padding,
        accentBorder: Color? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.padding = padding
        self.accentBorder = accentBorder
        self.content = content()
    }

    public var body: some View {
        content
            .padding(padding)
            .background(
                RoundedRectangle(cornerRadius: VGComponentTokens.Card.cornerRadius, style: .continuous)
                    .fill(VGComponentTokens.Card.background)
            )
            .overlay(
                RoundedRectangle(cornerRadius: VGComponentTokens.Card.cornerRadius, style: .continuous)
                    .strokeBorder(
                        accentBorder ?? VGComponentTokens.Card.border,
                        lineWidth: accentBorder != nil
                            ? VGComponentTokens.Card.accentBorderWidth
                            : VGComponentTokens.Card.borderWidth
                    )
            )
    }
}

public struct VGPageHeader<Actions: View>: View {
    let title: String
    let subtitle: String?
    let actions: Actions

    public init(
        title: String,
        subtitle: String? = nil,
        @ViewBuilder actions: () -> Actions = { EmptyView() }
    ) {
        self.title = title
        self.subtitle = subtitle
        self.actions = actions()
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: VGTokens.Spacing.gridGap) {
                VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                    Text(title)
                        .font(VGTokens.Typography.pageTitle)
                        .foregroundStyle(VGTokens.Colors.textPrimary)

                    if let subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(VGTokens.Typography.caption)
                            .foregroundStyle(VGTokens.Colors.textSecondary)
                            .lineLimit(1)
                    }
                }

                Spacer(minLength: VGTokens.Spacing.gridGap)

                actions
            }
            .padding(.horizontal, VGTokens.Spacing.pagePadding)
            .padding(.vertical, VGTokens.Spacing.cardPadding)

            Divider()
                .opacity(0.6)
        }
    }
}

public struct VGSectionHeader<Trailing: View>: View {
    let title: String
    let subtitle: String?
    let trailing: Trailing

    public init(
        _ title: String,
        subtitle: String? = nil,
        @ViewBuilder trailing: () -> Trailing = { EmptyView() }
    ) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: VGPrimitives.Space.s2) {
                Text(title)
                    .font(VGTokens.Typography.cardTitle)
                    .foregroundStyle(VGTokens.Colors.textPrimary)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(VGTokens.Typography.caption)
                        .foregroundStyle(VGTokens.Colors.textSecondary)
                }
            }
            Spacer()
            trailing
        }
    }
}

public struct VGStatusBadge: View {
    public enum Tone {
        case protected
        case warning
        case danger
        case accent
        case neutral

        var color: Color {
            switch self {
            case .protected: return VGTokens.Colors.statusProtected
            case .warning: return VGTokens.Colors.statusWarning
            case .danger: return VGTokens.Colors.statusDanger
            case .accent: return VGTokens.Colors.accentPrimary
            case .neutral: return VGTokens.Colors.textSecondary
            }
        }
    }

    let text: String
    let tone: Tone
    let showDot: Bool

    public init(_ text: String, tone: Tone = .neutral, showDot: Bool = false) {
        self.text = text
        self.tone = tone
        self.showDot = showDot
    }

    public var body: some View {
        HStack(spacing: VGPrimitives.Space.s4) {
            if showDot {
                Circle()
                    .fill(tone.color)
                    .frame(width: VGComponentTokens.Badge.dotSize, height: VGComponentTokens.Badge.dotSize)
                    .accessibilityHidden(true)
            }
            Text(text)
                .font(VGTokens.Typography.badge)
                .monospacedDigit()
        }
        .padding(.horizontal, VGComponentTokens.Badge.horizontalPadding)
        .padding(.vertical, VGComponentTokens.Badge.verticalPadding)
        .foregroundStyle(tone == .neutral ? VGTokens.Colors.textSecondary : tone.color)
        .background(
            RoundedRectangle(cornerRadius: VGComponentTokens.Badge.cornerRadius, style: .continuous)
                .fill(tone == .neutral ? VGTokens.Colors.surfaceLevel2 : tone.color.opacity(VGComponentTokens.Badge.fillOpacity))
        )
        .overlay(
            RoundedRectangle(cornerRadius: VGComponentTokens.Badge.cornerRadius, style: .continuous)
                .strokeBorder(
                    tone == .neutral ? VGTokens.Colors.borderSubtle : tone.color.opacity(VGComponentTokens.Badge.borderOpacity),
                    lineWidth: 0.5
                )
        )
    }
}

public struct VGKeyValueRow: View {
    let key: String
    let value: String
    let valueColor: Color
    let monospaced: Bool

    public init(
        _ key: String,
        value: String,
        valueColor: Color = VGTokens.Colors.textPrimary,
        monospaced: Bool = true
    ) {
        self.key = key
        self.value = value
        self.valueColor = valueColor
        self.monospaced = monospaced
    }

    public var body: some View {
        HStack(alignment: .top, spacing: VGPrimitives.Space.s10) {
            Text(key)
                .font(VGTokens.Typography.caption)
                .foregroundStyle(VGTokens.Colors.textSecondary)
                .fixedSize(horizontal: true, vertical: false)

            Spacer(minLength: VGTokens.Spacing.inlineGap)

            Text(value)
                .font(monospaced ? VGTokens.Typography.monoCaption.weight(.medium) : VGTokens.Typography.captionEmphasis)
                .monospacedDigit()
                .foregroundStyle(valueColor)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
    }
}

public struct VGSearchField: View {
    let placeholder: String
    @Binding var text: String

    public init(_ placeholder: String, text: Binding<String>) {
        self.placeholder = placeholder
        self._text = text
    }

    public var body: some View {
        HStack(spacing: VGTokens.Spacing.inlineGap) {
            Image(systemName: "magnifyingglass")
                .font(VGTokens.Typography.caption)
                .foregroundStyle(VGTokens.Colors.textSecondary)
                .accessibilityHidden(true)

            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .font(VGTokens.Typography.body)

            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(VGTokens.Typography.caption)
                }
                .buttonStyle(VGIconButtonStyle())
                .help("Очистить поиск")
                .accessibilityLabel("Очистить поиск")
            }
        }
        .padding(.horizontal, VGPrimitives.Space.s10)
        .padding(.vertical, text.isEmpty ? VGPrimitives.Space.s6 : VGPrimitives.Space.s2)
        .frame(minHeight: 30)
        .background(
            RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                .fill(VGTokens.Colors.surfaceLevel2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: VGTokens.Radius.control, style: .continuous)
                .strokeBorder(VGTokens.Colors.borderSubtle, lineWidth: VGComponentTokens.Card.borderWidth)
        )
    }
}

public struct VGEmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    let actionTitle: String?
    let action: (() -> Void)?

    public init(
        icon: String,
        title: String,
        message: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil
    ) {
        self.icon = icon
        self.title = title
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
    }

    public var body: some View {
        VStack(spacing: VGTokens.Spacing.gridGap) {
            ZStack {
                RoundedRectangle(cornerRadius: VGTokens.Radius.card, style: .continuous)
                    .fill(VGTokens.Colors.surfaceLevel2)
                    .frame(width: 48, height: 48)
                Image(systemName: icon)
                    .font(.system(size: 20, weight: .medium))
                    .foregroundStyle(VGTokens.Colors.textSecondary)
            }
            .accessibilityHidden(true)

            VStack(spacing: VGTokens.Spacing.microGap) {
                Text(title)
                    .font(VGTokens.Typography.cardTitle)
                    .foregroundStyle(VGTokens.Colors.textPrimary)

                Text(message)
                    .font(VGTokens.Typography.caption)
                    .foregroundStyle(VGTokens.Colors.textSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)
                    .padding(.top, VGTokens.Spacing.microGap)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(VGPrimitives.Space.s32)
    }
}

public struct VGLoadingStateView: View {
    let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var body: some View {
        VStack(spacing: VGTokens.Spacing.gridGap) {
            ProgressView()
                .controlSize(.regular)
            Text(message)
                .font(VGTokens.Typography.caption)
                .foregroundStyle(VGTokens.Colors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(VGPrimitives.Space.s32)
    }
}

public struct VGErrorBanner: View {
    let message: String
    let retryTitle: String?
    let onRetry: (() -> Void)?

    public init(
        message: String,
        retryTitle: String? = nil,
        onRetry: (() -> Void)? = nil
    ) {
        self.message = message
        self.retryTitle = retryTitle
        self.onRetry = onRetry
    }

    public var body: some View {
        VGCard(padding: VGComponentTokens.Card.paddingCompact, accentBorder: VGTokens.Colors.statusDanger.opacity(0.35)) {
            HStack(spacing: VGPrimitives.Space.s10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(VGTokens.Colors.statusDanger)
                    .accessibilityHidden(true)
                Text(message)
                    .font(VGTokens.Typography.body)
                    .foregroundStyle(VGTokens.Colors.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: VGTokens.Spacing.inlineGap)
                if let retryTitle, let onRetry {
                    Button(retryTitle, action: onRetry)
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }
        }
    }
}

public struct VGCopyButton: View {
    let valueToCopy: String
    let label: String?
    let helpText: String
    let onCopied: (() -> Void)?

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isCopied = false

    public init(
        _ valueToCopy: String,
        label: String? = nil,
        helpText: String = "Скопировать",
        onCopied: (() -> Void)? = nil
    ) {
        self.valueToCopy = valueToCopy
        self.label = label
        self.helpText = helpText
        self.onCopied = onCopied
    }

    public var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(valueToCopy, forType: .string)
            withAnimation(VGTokens.Motion.snappy(reduceMotion: reduceMotion)) {
                isCopied = true
            }
            onCopied?()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                withAnimation(VGTokens.Motion.snappy(reduceMotion: reduceMotion)) {
                    isCopied = false
                }
            }
        } label: {
            HStack(spacing: VGPrimitives.Space.s4) {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                    .font(VGTokens.Typography.captionEmphasis)
                    .foregroundStyle(isCopied ? VGTokens.Colors.statusProtected : VGTokens.Colors.textSecondary)
                    .accessibilityHidden(true)
                if let label {
                    Text(isCopied ? "Скопировано" : label)
                        .font(VGTokens.Typography.captionEmphasis)
                        .foregroundStyle(isCopied ? VGTokens.Colors.statusProtected : VGTokens.Colors.textPrimary)
                }
            }
            .frame(
                minWidth: label == nil ? VGComponentTokens.Button.minIconHitTarget : nil,
                minHeight: VGComponentTokens.Button.minIconHitTarget
            )
            .padding(.horizontal, label == nil ? 0 : VGPrimitives.Space.s8)
            .contentTransition(reduceMotion ? .identity : .symbolEffect(.replace))
        }
        .buttonStyle(VGIconButtonStyle())
        .help(helpText)
        .accessibilityLabel(isCopied ? "Скопировано" : (label ?? helpText))
    }
}

public struct VGUnsavedChangesBar: View {
    let isApplying: Bool
    let onDiscard: () -> Void
    let onApply: () -> Void

    public var body: some View {
        VStack(spacing: 0) {
            Divider().opacity(0.6)
            HStack(spacing: VGTokens.Spacing.gridGap) {
                HStack(spacing: VGTokens.Spacing.inlineGap) {
                    Circle()
                        .fill(VGTokens.Colors.statusWarning)
                        .frame(width: 7, height: 7)
                        .accessibilityHidden(true)
                    Text("Есть несохранённые изменения правил")
                        .font(VGTokens.Typography.bodyEmphasis)
                        .foregroundStyle(VGTokens.Colors.textPrimary)
                }

                Spacer()

                Button("Сбросить", action: onDiscard)
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .disabled(isApplying)

                Button(action: onApply) {
                    HStack(spacing: VGPrimitives.Space.s6) {
                        if isApplying {
                            ProgressView()
                                .controlSize(.small)
                        }
                        Text("Применить изменения")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .disabled(isApplying)
            }
            .padding(.horizontal, VGTokens.Spacing.pagePadding)
            .padding(.vertical, VGTokens.Spacing.cardPaddingCompact)
            .background(VGTokens.Colors.statusWarning.opacity(0.08))
        }
    }
}

public struct VGHoverRowModifier: ViewModifier {
    let cornerRadius: CGFloat
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isHovered = false

    public func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(isHovered ? VGTokens.Colors.surfaceHover : .clear)
            )
            .onHover { hovering in
                withAnimation(VGTokens.Motion.hover(reduceMotion: reduceMotion)) {
                    isHovered = hovering
                }
            }
    }
}

public extension View {
    func vgHoverRow(cornerRadius: CGFloat = VGComponentTokens.Row.cornerRadius) -> some View {
        modifier(VGHoverRowModifier(cornerRadius: cornerRadius))
    }
}

// MARK: - Focus-Aware Native Button Styles

/// Accessible icon-only button style with 28pt minimum hit target, hover feedback, and visible focus ring.
public struct VGIconButtonStyle: ButtonStyle {
    let isDestructive: Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.isEnabled) private var isEnabled
    @FocusState private var isFocused: Bool
    @State private var isHovered = false

    public init(isDestructive: Bool = false) {
        self.isDestructive = isDestructive
    }

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(foregroundColor(isPressed: configuration.isPressed))
            .frame(
                minWidth: VGComponentTokens.Button.minIconHitTarget,
                minHeight: VGComponentTokens.Button.minIconHitTarget
            )
            .background(
                RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous)
                    .fill(backgroundColor(isPressed: configuration.isPressed))
            )
            .overlay(
                RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous)
                    .strokeBorder(
                        isFocused ? VGTokens.Colors.accentPrimary : .clear,
                        lineWidth: 2
                    )
            )
            .contentShape(RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous))
            .focusable()
            .focused($isFocused)
            .onHover { hovering in
                withAnimation(VGTokens.Motion.hover(reduceMotion: reduceMotion)) {
                    isHovered = hovering
                }
            }
            .opacity(isEnabled ? 1.0 : 0.45)
    }

    private func foregroundColor(isPressed: Bool) -> Color {
        if isDestructive && (isHovered || isPressed) {
            return VGTokens.Colors.statusDanger
        }
        return (isHovered || isPressed) ? VGTokens.Colors.textPrimary : VGTokens.Colors.textSecondary
    }

    private func backgroundColor(isPressed: Bool) -> Color {
        if isPressed {
            return VGTokens.Colors.sidebarSelection
        }
        if isHovered {
            return isDestructive ? VGTokens.Colors.statusDanger.opacity(0.12) : VGTokens.Colors.surfaceHover
        }
        return .clear
    }
}

/// Subtle surface button style for secondary/sidebar actions with hover, pressed state, and focus ring.
public struct VGSurfaceButtonStyle: ButtonStyle {
    let isHighlighted: Bool
    let highlightTint: Color

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.isEnabled) private var isEnabled
    @FocusState private var isFocused: Bool
    @State private var isHovered = false

    public init(isHighlighted: Bool = false, highlightTint: Color = VGTokens.Colors.accentPrimary) {
        self.isHighlighted = isHighlighted
        self.highlightTint = highlightTint
    }

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(
                RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous)
                    .fill(backgroundColor(isPressed: configuration.isPressed))
            )
            .overlay(
                RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous)
                    .strokeBorder(
                        isFocused
                            ? VGTokens.Colors.accentPrimary
                            : (isHighlighted ? highlightTint.opacity(0.35) : VGTokens.Colors.borderSubtle),
                        lineWidth: isFocused ? 2 : VGComponentTokens.Card.borderWidth
                    )
            )
            .contentShape(RoundedRectangle(cornerRadius: VGComponentTokens.Button.cornerRadius, style: .continuous))
            .focusable()
            .focused($isFocused)
            .onHover { hovering in
                withAnimation(VGTokens.Motion.hover(reduceMotion: reduceMotion)) {
                    isHovered = hovering
                }
            }
            .opacity(isEnabled ? 1.0 : 0.5)
    }

    private func backgroundColor(isPressed: Bool) -> Color {
        if isPressed {
            return isHighlighted ? highlightTint.opacity(0.22) : VGTokens.Colors.sidebarSelection
        }
        if isHovered {
            return isHighlighted ? highlightTint.opacity(0.18) : VGTokens.Colors.surfaceHover
        }
        return isHighlighted ? highlightTint.opacity(0.14) : VGTokens.Colors.surfaceLevel1
    }
}
