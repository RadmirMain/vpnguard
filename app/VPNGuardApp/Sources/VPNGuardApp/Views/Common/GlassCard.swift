import SwiftUI

public struct GlassCard<Content: View>: View {
    let content: Content
    var padding: CGFloat = VGTheme.cardPadding

    public init(padding: CGFloat = VGTheme.cardPadding, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    public var body: some View {
        VGCard(padding: padding) {
            content
        }
    }
}
