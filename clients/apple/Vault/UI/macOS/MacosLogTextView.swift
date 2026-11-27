#if os(macOS)
import AppKit
import SwiftUI

/// AppKit renders large logs lazily and keeps text selection responsive.
struct LogTextView: NSViewRepresentable {
    let text: String
    var followsTail = true
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let view = scroll.documentView as? NSTextView {
            view.isEditable = false
            view.isSelectable = true
            view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            view.textContainerInset = NSSize(width: 16, height: 16)
            view.backgroundColor = NSColor(Color(vaultHex: "171B2E"))
            view.textColor = NSColor(Color(vaultHex: "C7D2FE"))
            view.insertionPointColor = NSColor(Color(vaultHex: "C7D2FE"))
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView, view.string != text else { return }
        let origin = scroll.contentView.bounds.origin
        let selection = view.selectedRange()
        view.string = text
        let location = min(selection.location, view.string.utf16.count)
        view.setSelectedRange(NSRange(location: location, length: min(selection.length, view.string.utf16.count - location)))
        if followsTail {
            // Wait for SwiftUI to size the scroll view before revealing the tail.
            DispatchQueue.main.async { [weak scroll, weak view] in
                guard let scroll, let view, view.string == text,
                      view.window?.occlusionState.contains(.visible) == true else { return }
                scroll.layoutSubtreeIfNeeded()
                if let container = view.textContainer {
                    view.layoutManager?.ensureLayout(for: container)
                }
                view.scrollToEndOfDocument(nil)
            }
        } else { scroll.contentView.scroll(to: origin)
            scroll.reflectScrolledClipView(scroll.contentView)
        }
    }
}
#endif
