import SwiftUI
import AppKit

// MARK: - Theme Tokens
public enum VGTheme {
    // MARK: Adaptive Surfaces (Dark Mode native)
    public static let backgroundContent = Color(nsColor: .windowBackgroundColor)

    public static let surfaceLevel1 = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.045)
            : NSColor.black.withAlphaComponent(0.03)
    })

    public static let surfaceLevel2 = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.06)
            : NSColor.black.withAlphaComponent(0.045)
    })

    public static let surfaceHover = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.09)
            : NSColor.black.withAlphaComponent(0.075)
    })

    public static let sidebarSelection = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.10)
            : NSColor.black.withAlphaComponent(0.08)
    })

    public static let borderSubtle = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.08)
            : NSColor.black.withAlphaComponent(0.08)
    })

    // MARK: Semantic Colors
    /// Muted emerald for active protection, PASS, Direct
    public static let statusProtected = Color(red: 0.20, green: 0.78, blue: 0.55)
    /// Amber for pauses, warnings, Touch ID prompts
    public static let statusWarning = Color(red: 0.94, green: 0.65, blue: 0.18)
    /// Muted red for disconnect, block, FAIL, delete
    public static let statusDanger = Color(red: 0.90, green: 0.34, blue: 0.34)
    /// Primary accent for primary CTAs and interactive controls
    public static let accentPrimary = Color(red: 0.28, green: 0.52, blue: 0.96)

    // MARK: Radii
    public static let radiusCard: CGFloat = 12
    public static let radiusControl: CGFloat = 8
    public static let radiusBadge: CGFloat = 6

    // MARK: Spacing
    public static let pagePadding: CGFloat = 24
    public static let sheetPadding: CGFloat = 20
    public static let cardPadding: CGFloat = 16
    public static let sectionSpacing: CGFloat = 20
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

    public static func formatLocalTime(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "ru_RU")
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }

    /// Converts raw ANSI log text into clean AttributedString with semantic level highlighting
    public static func attributedLogs(from raw: String, searchQuery: String = "") -> AttributedString {
        let cleaned = stripANSI(raw)
        let lines = cleaned.components(separatedBy: .newlines)
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

            // Highlight search query matches softly
            let trimmedQuery = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedQuery.isEmpty,
               let range = attrLine.range(of: trimmedQuery, options: .caseInsensitive) {
                attrLine[range].backgroundColor = VGTheme.statusWarning.opacity(0.28)
            }

            result.append(attrLine)
            if idx < lines.count - 1 {
                result.append(AttributedString("\n"))
            }
        }
        return result
    }
}

// MARK: - Reusable Components

public struct VGCard<Content: View>: View {
    let padding: CGFloat
    let accentBorder: Color?
    let content: Content

    public init(
        padding: CGFloat = VGTheme.cardPadding,
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
                RoundedRectangle(cornerRadius: VGTheme.radiusCard, style: .continuous)
                    .fill(VGTheme.surfaceLevel1)
            )
            .overlay(
                RoundedRectangle(cornerRadius: VGTheme.radiusCard, style: .continuous)
                    .strokeBorder(accentBorder ?? VGTheme.borderSubtle, lineWidth: accentBorder != nil ? 1 : 0.75)
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
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(.primary)

                    if let subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer(minLength: 12)

                actions
            }
            .padding(.horizontal, VGTheme.pagePadding)
            .padding(.vertical, 16)

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
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
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
            case .protected: return VGTheme.statusProtected
            case .warning: return VGTheme.statusWarning
            case .danger: return VGTheme.statusDanger
            case .accent: return VGTheme.accentPrimary
            case .neutral: return .secondary
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
        HStack(spacing: 5) {
            if showDot {
                Circle()
                    .fill(tone.color)
                    .frame(width: 6, height: 6)
            }
            Text(text)
                .font(.system(size: 10, weight: .semibold))
                .monospacedDigit()
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .foregroundStyle(tone == .neutral ? Color.secondary : tone.color)
        .background(
            RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous)
                .fill(tone == .neutral ? VGTheme.surfaceLevel2 : tone.color.opacity(0.14))
        )
        .overlay(
            RoundedRectangle(cornerRadius: VGTheme.radiusBadge, style: .continuous)
                .strokeBorder(tone == .neutral ? VGTheme.borderSubtle : tone.color.opacity(0.25), lineWidth: 0.5)
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
        valueColor: Color = .primary,
        monospaced: Bool = true
    ) {
        self.key = key
        self.value = value
        self.valueColor = valueColor
        self.monospaced = monospaced
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(key)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: true, vertical: false)

            Spacer(minLength: 8)

            Text(value)
                .font(.system(size: 11, weight: .medium, design: monospaced ? .monospaced : .default))
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
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)

            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .font(.system(size: 12))

            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Очистить поиск")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                .fill(VGTheme.surfaceLevel2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: VGTheme.radiusControl, style: .continuous)
                .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
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
        VStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: VGTheme.radiusCard, style: .continuous)
                    .fill(VGTheme.surfaceLevel2)
                    .frame(width: 48, height: 48)
                Image(systemName: icon)
                    .font(.system(size: 20, weight: .medium))
                    .foregroundStyle(.secondary)
            }

            VStack(spacing: 4) {
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.primary)

                Text(message)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)
                    .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(32)
    }
}

public struct VGCopyButton: View {
    let valueToCopy: String
    let label: String?
    let helpText: String
    let onCopied: (() -> Void)?

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
            withAnimation(.snappy(duration: 0.2)) {
                isCopied = true
            }
            onCopied?()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                withAnimation(.snappy(duration: 0.2)) {
                    isCopied = false
                }
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(isCopied ? VGTheme.statusProtected : .secondary)
                if let label {
                    Text(isCopied ? "Скопировано" : label)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(isCopied ? VGTheme.statusProtected : .primary)
                }
            }
            .contentTransition(.symbolEffect(.replace))
        }
        .buttonStyle(.plain)
        .help(helpText)
    }
}

public struct VGUnsavedChangesBar: View {
    let isApplying: Bool
    let onDiscard: () -> Void
    let onApply: () -> Void

    public var body: some View {
        VStack(spacing: 0) {
            Divider().opacity(0.6)
            HStack(spacing: 12) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(VGTheme.statusWarning)
                        .frame(width: 7, height: 7)
                    Text("Есть несохранённые изменения правил")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                }

                Spacer()

                Button("Сбросить", action: onDiscard)
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .disabled(isApplying)

                Button(action: onApply) {
                    HStack(spacing: 6) {
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
            .padding(.horizontal, VGTheme.pagePadding)
            .padding(.vertical, 12)
            .background(VGTheme.statusWarning.opacity(0.08))
        }
    }
}

public struct VGHoverRowModifier: ViewModifier {
    let cornerRadius: CGFloat
    @State private var isHovered = false

    public func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(isHovered ? VGTheme.surfaceHover : VGTheme.surfaceLevel1)
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(VGTheme.borderSubtle, lineWidth: 0.75)
            )
            .onHover { hovering in
                withAnimation(.snappy(duration: 0.15)) {
                    isHovered = hovering
                }
            }
    }
}

public extension View {
    func vgHoverRow(cornerRadius: CGFloat = VGTheme.radiusControl) -> some View {
        modifier(VGHoverRowModifier(cornerRadius: cornerRadius))
    }
}
