#if os(iOS)
import SwiftUI
import UIKit

struct IosKeyboardDismissal: UIViewRepresentable {
    static func dismiss() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }

    func makeUIView(context: Context) -> AnchorView { AnchorView() }
    func updateUIView(_ view: AnchorView, context: Context) {}

    static func dismantleUIView(_ view: AnchorView, coordinator: ()) {
        view.detach()
    }

    final class AnchorView: UIView, UIGestureRecognizerDelegate {
        private lazy var tap: UITapGestureRecognizer = {
            let gesture = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
            gesture.cancelsTouchesInView = false
            gesture.delaysTouchesEnded = false
            gesture.delegate = self
            return gesture
        }()

        override func didMoveToWindow() {
            super.didMoveToWindow()
            detach()
            window?.addGestureRecognizer(tap)
        }

        func detach() {
            tap.view?.removeGestureRecognizer(tap)
        }

        @objc private func dismissKeyboard() {
            window?.endEditing(true)
        }

        func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
            var view = touch.view
            while let candidate = view {
                if (candidate as? UITextField)?.isEnabled == true ||
                    (candidate as? UITextView)?.isEditable == true {
                    return false
                }
                view = candidate.superview
            }
            return true
        }

        func gestureRecognizer(
            _ gestureRecognizer: UIGestureRecognizer,
            shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
        ) -> Bool {
            true
        }
    }
}
#endif
