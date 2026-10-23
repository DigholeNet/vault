#if os(macOS)
import AppKit
import SwiftUI

/// Visible keyboard selection for custom actions. Activation is routed by the
/// owning window so it works without changing system-wide keyboard settings.
private struct MacosKeyboardAction<ID: Hashable>: ViewModifier {
    @Binding var focus: ID?
    let id: ID
    var enabled: Bool
    var circular: Bool
    let action: () -> Void

    func body(content: Content) -> some View {
        content
            .overlay {
                if focus == id {
                    Group {
                        if circular { Circle().strokeBorder(Color.accentColor, lineWidth: 2) }
                        else { RoundedRectangle(cornerRadius: 6).strokeBorder(Color.accentColor, lineWidth: 2) }
                    }.padding(-3).allowsHitTesting(false)
                }
            }
            .accessibilityAction { if enabled { action() } }
    }
}

extension View {
    func macosKeyboardAction<ID: Hashable>(focus: Binding<ID?>, id: ID,
        enabled: Bool = true, circular: Bool = false, action: @escaping () -> Void) -> some View {
        modifier(MacosKeyboardAction(focus: focus, id: id, enabled: enabled, circular: circular, action: action))
    }
}


/// Intercept navigation before AppKit's native Tab traversal can skip custom
/// controls. The monitor is restricted to this view's own window and ignores IME
/// composition; it never observes another app or changes system preferences.
private struct MacosKeyboardNavigation: NSViewRepresentable {
    let handler: (NSEvent) -> Bool
    final class MonitorView: NSView {
        var handler: (NSEvent) -> Bool = { _ in false }
        private var monitor: Any?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            stop()
            guard window != nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown]) { [weak self] event in
                guard let self, let window = self.window, event.window === window, window.attachedSheet == nil else { return event }
                if let editor = window.firstResponder as? NSTextView, editor.hasMarkedText() { return event }
                return self.handler(event) ? nil : event
            }
        }
        func stop() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }
        deinit { stop() }
    }
    func makeNSView(context: Context) -> MonitorView {
        let view = MonitorView()
        view.handler = handler
        return view
    }
    func updateNSView(_ view: MonitorView, context: Context) { view.handler = handler }
    static func dismantleNSView(_ view: MonitorView, coordinator: ()) { view.stop() }
}

extension View {
    func macosKeyboardNavigation(_ handler: @escaping (NSEvent) -> Bool) -> some View {
        background(MacosKeyboardNavigation(handler: handler).frame(width: 0, height: 0))
    }
}
#endif
