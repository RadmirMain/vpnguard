import SwiftUI

public struct ToastView: View {
    let message: String
    let isError: Bool

    public var body: some View {
        HStack(spacing: VGTokens.Spacing.inlineGap) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(isError ? VGTokens.Colors.statusDanger : VGTokens.Colors.statusProtected)
                .font(.system(size: 13, weight: .semibold))
                .accessibilityHidden(true)

            Text(message)
                .font(VGTokens.Typography.captionEmphasis)
                .foregroundStyle(VGTokens.Colors.textPrimary)
                .lineLimit(2)
        }
        .padding(.horizontal, VGPrimitives.Space.s14)
        .padding(.vertical, VGPrimitives.Space.s8)
        .background(.regularMaterial, in: Capsule())
        .overlay(
            Capsule()
                .strokeBorder(
                    (isError ? VGTokens.Colors.statusDanger : VGTokens.Colors.statusProtected).opacity(0.3),
                    lineWidth: VGComponentTokens.Card.borderWidth
                )
        )
        .shadow(color: .black.opacity(0.2), radius: 10, x: 0, y: 4)
        .accessibilityElement(children: .combine)
    }
}
