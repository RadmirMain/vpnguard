import SwiftUI

public struct GlassCard<Content: View>: View {
    let content: Content
    var padding: CGFloat = 16
    
    public init(padding: CGFloat = 16, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }
    
    public var body: some View {
        content
            .padding(padding)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(Color.primary.opacity(0.08), lineWidth: 1)
            )
    }
}
