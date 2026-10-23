#if os(iOS)
import SwiftUI
import UIKit

/// Native text selection and lazy layout keep large logs responsive.
struct LogTextView: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.isEditable = false
        view.isSelectable = true
        let font = UIFont.preferredFont(forTextStyle: .footnote)
        let descriptor = font.fontDescriptor.withDesign(.monospaced) ?? font.fontDescriptor
        view.font = UIFont(descriptor: descriptor, size: 0)
        view.adjustsFontForContentSizeCategory = true
        view.backgroundColor = .secondarySystemGroupedBackground
        view.textContainerInset = UIEdgeInsets(top: 12, left: 10, bottom: 12, right: 10)
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        guard view.text != text else { return }
        let selection = view.selectedRange
        view.text = text
        let location = min(selection.location, text.utf16.count)
        view.selectedRange = NSRange(location: location, length: min(selection.length, text.utf16.count - location))
        view.scrollRangeToVisible(NSRange(location: text.utf16.count, length: 0))
    }
}
#endif
