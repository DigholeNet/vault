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
        let font = UIFont.preferredFont(forTextStyle: .caption1)
        let descriptor = font.fontDescriptor.withDesign(.monospaced) ?? font.fontDescriptor
        view.font = UIFont(descriptor: descriptor, size: 0)
        view.adjustsFontForContentSizeCategory = true
        view.backgroundColor = UIColor(VaultTheme.surface)
        view.textColor = UIColor(VaultTheme.textSecondary)
        view.textContainerInset = UIEdgeInsets(top: 16, left: 12, bottom: 16, right: 12)
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        guard view.text != text else { return }
        let selection = view.selectedRange
        view.text = text
        let location = min(selection.location, text.utf16.count)
        view.selectedRange = NSRange(location: location, length: min(selection.length, text.utf16.count - location))
        // SwiftUI may not have assigned the viewport when the text first arrives.
        DispatchQueue.main.async { [weak view] in
            guard let view, view.text == text else { return }
            view.layoutIfNeeded()
            view.scrollRangeToVisible(NSRange(location: text.utf16.count, length: 0))
        }
    }
}
#endif
