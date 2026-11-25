import SwiftUI

public struct ToastView: View {
    let message: String
    let isError: Bool
    
    public var body: some View {
        HStack(spacing: 10) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundColor(isError ? .red : .green)
                .font(.system(size: 14, weight: .semibold))
            
            Text(message)
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(.primary)
                .lineLimit(2)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.regularMaterial, in: Capsule())
        .overlay(
            Capsule()
                .stroke(isError ? Color.red.opacity(0.3) : Color.green.opacity(0.3), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.15), radius: 8, x: 0, y: 4)
    }
}
