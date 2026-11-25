import SwiftUI

public struct ToastView: View {
    let message: String
    let isError: Bool

    public var body: some View {
        HStack(spacing: 10) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(isError ? VGTheme.statusDanger : VGTheme.statusProtected)
                .font(.system(size: 13, weight: .semibold))

            Text(message)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.primary)
                .lineLimit(2)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(.regularMaterial, in: Capsule())
        .overlay(
            Capsule()
                .strokeBorder(
                    (isError ? VGTheme.statusDanger : VGTheme.statusProtected).opacity(0.3),
                    lineWidth: 0.75
                )
        )
        .shadow(color: .black.opacity(0.2), radius: 10, x: 0, y: 4)
    }
}
