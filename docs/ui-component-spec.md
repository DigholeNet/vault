# Vault UI Component and Visual Acceptance Specification

This specification covers Status, Configure, Diagnostics, Runtime Logs, and About on Android, iOS, and macOS. The clients share an information hierarchy, status messages, action meanings, and icon shapes. Navigation, input, windows, and system feedback follow each platform’s conventions.

[View the Vault UI concept](screenshots/vault-ui-concept.svg)

## Design review

- The original mobile concept used 10-unit navigation labels, field labels as small as 8.5 units, and 36-unit inputs. The revised concept raises navigation and field labels to 12 units, shows 52-unit configuration inputs, and hides the bottom navigation in the editor to give the form more room.
- On a white surface, the original `#8A96A8` label gray had a contrast ratio of approximately 3.00:1. The original `#64748B` secondary text had a ratio of approximately 4.45:1 on the page background. The revised concept uses `#526078` for functional secondary text on light surfaces and strengthens field outlines.
- Regular and failure screens now share server, navigation, and brand assets. Diagnostic icons retain the same outline when a row expands. Traffic direction uses arrows and labels, while failure and permission states use distinct semantic colors.
- The configuration feedback section has enough height to show its full card outlines and bottom spacing.
- Neutral surfaces and dividers use fewer colors. Indigo marks primary actions, selection, links, and progress. A solid navy card identifies an active connection. Rose marks failures, and amber marks permissions and warnings.
- The original Android navigation used a 66dp container and 10sp labels, which could clip with larger text. Apple configuration and diagnostic screens also mixed filled and outline icons. The sections below define the component behavior and visual acceptance criteria.

## Dimensions and typography

The values below are baselines at the default system text size. Android uses dp for layout and sp for text. Apple platforms use pt, and iOS text scales with Dynamic Type. Measure available width inside the system bars and display cutouts. Allow controls to grow for text, guidance, and errors.

| Component | Android | iOS | macOS |
| --- | --- | --- | --- |
| Minimum action area | 48 × 48dp | 44 × 44pt | 28 × 28pt for custom controls. Use standard sizes for native controls. |
| Typography | Page title 28sp, card title 16sp, body and actions 14–16sp, labels and technical details 12sp | Page title 28pt, card title 16pt, body 17pt, actions 15pt, labels and technical details 12–13pt | Content title 22pt, card title 15pt, body and actions 13pt, technical details 12pt |
| Pages and cards | 20dp page inset, 16dp at widths of 360dp or less, 16dp group spacing and card padding, 20dp radius | 20pt page inset, 16pt at widths of 360pt or less, 16pt group spacing and card padding, 20pt radius | 20pt window content inset, 16pt popover inset, 12–16pt group spacing and card padding, 14pt radius |
| Buttons and fields | Buttons at least 48dp high and inputs at least 52dp high | Buttons at least 44pt high and inputs at least 48pt high | Custom buttons and fields at least 28pt high, with 36pt recommended for form rows |
| Navigation and switching | Four bottom destinations with 12sp labels and 24dp icons. Each target is at least 52dp high. Use 6dp above and below the bar, plus the system bottom inset. Use 6dp of top and bottom padding inside each destination. Leave 2dp between the active indicator and the label. The bar grows with its labels. Diagnostic segments are at least 48dp high. | Native `TabView` and `NavigationStack`. Diagnostic segments have a minimum 44pt action area. System navigation uses system text sizes. | A 340pt menu bar popover. Settings and Diagnostics use native windows, with sidebar rows at least 32pt high. |
| Connection card | 24dp radius, 76dp power button, 38dp icon | 24pt radius, 76pt power button, 38pt icon | 20pt popover card radius, 64pt power button, 32pt icon |

Icons may be smaller than their action areas. Make the full row interactive for profile selectors, expandable diagnostics, and toggles. Size secondary icons according to the table. Use system fonts for body and status text, with system font fallback for languages such as Chinese and Japanese. Use tabular numerals for durations and traffic metrics, and the system monospaced font for addresses and logs. On macOS, use the system control font and verify the minimum window sizes and display scaling.

### Narrow layouts, larger text, and safe areas

- **Android** uses Views and Material 3. Let rows, bottom navigation, and form containers measure their content and enforce a minimum height. Use sp for text and dp for spacing and action areas. Allow enough vertical room for fallback fonts. On Android 14 and later, test nonlinear scaling at the largest system font size. Coordinate the system bars, cutouts, and keyboard insets through a single `WindowInsetsCompat` layer. Use system Back in the editor. When the keyboard opens, hide the bottom navigation and scroll the active field and its error into view. Restore navigation and scroll position as appropriate when the keyboard closes. [Android touch targets](https://developer.android.com/guide/topics/ui/accessibility/apps) · [Android font scaling](https://developer.android.com/about/versions/14/features#non-linear-font-scaling) · [Android window insets](https://developer.android.com/develop/ui/views/layout/edge-to-edge)
- **iOS** uses `TabView`, `NavigationStack`, and system safe areas. Profile Details uses the native Back control and a toolbar Save action, with the tab bar hidden. Use system text styles or `@ScaledMetric` for custom sizes. Prefer vertical layouts at accessibility text sizes. Keep the active field, its error, and Save reachable when the keyboard appears. [Apple layout guidance](https://developer.apple.com/design/human-interface-guidelines/layout)
- **macOS** keeps connection status, actions, and shortcuts in the menu bar popover. Settings, diagnostics, and logs use native windows. Settings opens with an 800 × 620pt content area, a 150pt sidebar, and the native title bar. The macOS visual concept uses the measured 800 × 652pt window frame. Make all actions reachable by keyboard, preserve a visible focus ring, and use Escape to dismiss or cancel where applicable. Provide system scrolling for shorter windows. Test Settings at its 680 × 520pt minimum frame and Diagnostics at its 960 × 720pt minimum frame. [Apple accessibility guidance](https://developer.apple.com/design/human-interface-guidelines/accessibility)
- **Reflow** at widths of 360dp or 360pt or less, at accessibility text sizes, or when content cannot fit on one line. Stack the profile name and action hint, address labels and values, and Uplink and Downlink metrics. Let technical values wrap and preserve the original value when copied. Allow two lines for navigation labels where needed. If the complete label still cannot fit, use a meaningful localized short label and retain the full accessible name. Forms, guidance, and results can scroll vertically. Logs may scroll within their own region.

## Icons and semantic colors

Use monochrome outline icons for actions. Shared custom icons use a 24 × 24 view box, a 1.8-unit stroke, and rounded caps. Standard action icons are 24dp or 24pt on mobile and 18–20pt on macOS. Field accessories and supporting icons may use 16–20 units while retaining the action areas specified above. Android uses VectorDrawable assets. Apple platforms use equivalent regular outline SF Symbols or the shared vector when the shape differs substantially. Keep the icon shape consistent across selection states and indicate selection through color, a tinted surface, and accessibility semantics. The app mark, system controls, and small status dots follow their own conventions.

Diagnostic and selected-profile status markers use a single outline circle with a transparent interior. The circle and its symbol share one foreground color. Tinted surfaces indicate the selected state of navigation controls.

| Use | Icons | Color and state |
| --- | --- | --- |
| Primary navigation | Bars for Status, sliders for Configure, a waveform for Diagnostics, an information circle for About | Secondary content color when unselected. Indigo and a pale indigo surface when selected. |
| Connection and recovery | Power, circular retry arrow, shield or lock for permissions, progress indicator while working | Indigo for connect and retry, rose for failure, amber for VPN permissions. |
| Lists and forms | Server rack, back and disclosure arrows, eye and crossed-out eye | Secondary content color for accessories and indigo for key actions. Rotate the same disclosure glyph for expanded rows. |
| Diagnostics | Checkmark for passed, exclamation mark for failed, dash for skipped | Indigo for passed, rose for failed, and secondary content color for skipped. An incomplete result uses a monochrome amber warning icon. The outline and exclamation mark use the same foreground color. |
| Addresses, traffic, and logs | Globe or server rack, up and down arrows, overlapping documents for copy, trash can for clear | Secondary content color for traffic arrows and the primary text color for rates. Use secondary content color or indigo for copy, and rose for delete and clear. |

| Role | Light | Dark |
| --- | --- | --- |
| Page background / card | `#F6F7FB` / `#FFFFFF` | `#0F1220` / `#171B2E` |
| Primary / secondary text | `#172033` / `#526078` | `#F1F5F9` / `#A7B0C2` |
| Accent / text on accent | `#4F46E5` / `#FFFFFF` | `#A5B4FC` / `#1E1B4B` |
| Neutral surface / selected surface | `#EDF0F5` / `#EEF0FF` | `#20253A` / `#292D55` |
| Connected card | `#18244D` | `#25355F` |
| Connected card primary / secondary text | `#F1F5F9` / `#D7DFEF` | `#F1F5F9` / `#D7DFEF` |
| Failure and destructive foreground / failure surface | `#BE123C` / `#FFF1F2` | `#FDA4AF` / `#3B1D2A` |
| Permission foreground | `#A16207` | `#FACC15` |
| Diagnostic warning foreground / surface | `#92400E` / `#FFFBEB` | `#FCD34D` / `#372A19` |
| Decorative divider / editable field outline | `#DEE2EC` / `#748199` | `#30374E` / `#838FA9` |
| Disabled or decorative elements | `#8A96A8` | `#8A96A8` |

Body text, functional labels, and errors must reach 4.5:1 against their actual background. Icons needed to identify actions, editable field outlines, and focus rings must reach 3:1. Express status through text and an icon. Combine decorative graphics with their parent control for accessibility, and give icon-only buttons an action name and the applicable selected or expanded state. [WCAG text contrast](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) · [WCAG non-text contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html)

## Component states and interactions

| Component | Behavior |
| --- | --- |
| Connection card | Show “Add Profile” when empty and “Connect” when disconnected. Use a navy card with “Disconnect” when connected. Show a neutral surface, status text, and progress while connecting, reconnecting, or disconnecting. Prevent duplicate requests. Show a readable failure reason and offer “Retry,” or “Authorize VPN” when permission is required. On mobile, the icon and action text form one control. On macOS, use the circular icon as the single popover action. Give it a tooltip and an accessible name that match the current action. Show press, disabled, and keyboard focus states, and respect Reduce Motion. |
| macOS connection feedback | Use indigo progress for connecting and reconnecting and a neutral badge while disconnecting. Keep Disconnect available during reconnection. Show elapsed time, addresses, and traffic when the tunnel is connected. Use the iOS status titles for the macOS menu bar label. |
| Profile selection and editing | Identify the selected row with a checkmark and an accessible selected state. Let long names, lock reasons, and field errors wrap. Preserve input during saves, block duplicate submissions, and display errors below the associated field. Give the password toggle “Show password” and “Hide password” labels, and retain focus when it changes. Use system confirmation for deletion. |
| Cancelling diagnostics | Replace the run button with a secondary “Cancel checks” action during a run. A tap stops progress updates immediately. On Apple platforms, show “Checks cancelled” and restore “Run again” while the app finishes stopping the old run in the background. On Android, briefly show “Cancelling…” if the worker is still stopping. Retain completed results from the current run and label unrun checks “Not measured.” Direct and tunnel checks use the same flow. On macOS, place the action in the initial callout or below the summary within the result card. The top row contains the tab switcher. |
| Diagnostics and logs | Make the full diagnostic row expand and label outcomes as passed, failed, or skipped. Allow failure details and long domains to expand or wrap and expose the full value for copying. Logs support selection, copying, and clearing, with system confirmation before clearing. Provide text for loading, empty, result, and failure states, and announce progress or results at appropriate intervals. |
| Data and guidance | Show available network details, elapsed time, and traffic when connected. Hide unavailable addresses. Associate errors and warnings with the relevant content. Avoid announcing every update to the connection timer or live traffic. |
| About | Use the page or window background. Center the app icon, name, version and build number, one sentence of product information, the repository link showing the full address `https://github.com/DigholeNet/vault`, and copyright. Use the appropriate text and accent colors in dark mode. |

## Acceptance matrix

| Platform | Verify whenever shared components change |
| --- | --- |
| Android | Test narrow layouts at 320dp and 360dp and a typical width near 412dp. Cover default and maximum font sizes, a larger display size, gesture and three-button navigation, cutouts, landscape, and the open keyboard. Include at least one non-Pixel environment to verify font fallback and system insets. |
| iOS | Test a small iPhone around 375pt wide and an iPhone with a notch or Dynamic Island, at default and maximum accessibility text sizes. Cover the open keyboard, system Back, VoiceOver, and Reduce Motion. |
| macOS | Test the menu bar popover and both windows at typical and minimum sizes, in light and dark mode. Complete primary actions with Tab, Shift-Tab, Space or Return, and Escape. Check VoiceOver order, focus, and native popovers. |

- Cover light and dark mode, Chinese, English, and longer Spanish or Japanese labels. Use long profile names, full IPv6 addresses, long domains, and multiline errors to test reflow.
- With the same test data, check disconnected, connected, and failure states, permission cancellation, save validation errors, diagnostic expansion and cancellation, and log copying. Confirm that key text stays visible, action areas meet their minimums, system UI leaves controls unobstructed, complete values can be copied, and icons retain the same meaning across platforms.
- Include default screenshots for all three platforms when changing shared components. Add a relevant screenshot at the largest Android font size on a narrow screen, the largest iOS accessibility text size, and the smallest macOS window. Use screenshots for layout comparisons and test action areas, keyboard access, and announcements interactively.

## Implementation entry points

- The Android clients use [values](../clients/android/app/src/main/res/values), [values-night](../clients/android/app/src/main/res/values-night), and the [bottom navigation color selector](../clients/android/app/src/main/res/color/bottom_nav_color.xml) for colors, type, and styles. Reuse icons from [drawable](../clients/android/app/src/main/res/drawable). Bottom navigation and window insets are handled in [activity_main.xml](../clients/android/app/src/main/res/layout/activity_main.xml) and [MainActivity.kt](../clients/android/app/src/main/java/net/dighole/vault/MainActivity.kt).
- Apple dynamic colors and shared cards are defined in [VaultTheme.swift](../clients/apple/Vault/UI/Shared/VaultTheme.swift). iOS navigation is in [IosMainView.swift](../clients/apple/Vault/UI/iOS/IosMainView.swift). The macOS menu bar popover and windows are managed by [MacosMenuView.swift](../clients/apple/Vault/UI/macOS/MacosMenuView.swift) and [WindowManager.swift](../clients/apple/Vault/UI/macOS/WindowManager.swift).
