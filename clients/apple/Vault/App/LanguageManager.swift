//
//  LanguageManager.swift
//  Vault
//
//
//  Runtime language override with instant switching.
//
//  Apple platforms resolve Bundle.main's localization once per process, so
//  the standard `AppleLanguages` override requires a restart. To switch
//  instantly we bypass it: user-facing strings are looked up via `tr(_:)`
//  in the selected language's .lproj bundle, and SwiftUI views observe
//  `language` (via @EnvironmentObject) to re-render.
//

import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case en
    case zhHans = "zh-Hans"

    var id: String { rawValue }

    /// Language names are intentionally NOT localized: each is shown in
    /// its own tongue (same convention as the Android client).
    var displayName: String {
        switch self {
        case .system: return LanguageManager.shared.tr("System Default")
        case .en: return "English"
        case .zhHans: return "中文 (简体)"
        }
    }

    /// The .lproj bundle holding this language's string tables, or nil for
    /// `system` (Bundle.main follows the OS language) and `en` (the
    /// development language — the lookup keys ARE the English text).
    fileprivate func makeBundle() -> Bundle? {
        guard self == .zhHans,
              let path = Bundle.main.path(forResource: rawValue, ofType: "lproj")
        else { return nil }
        return Bundle(path: path)
    }
}

final class LanguageManager: ObservableObject {
    static let shared = LanguageManager()

    private static let defaultsKey = "appLanguage"

    /// The current override; `system` follows the OS language.
    @Published var language: AppLanguage {
        didSet {
            UserDefaults.standard.set(language.rawValue, forKey: Self.defaultsKey)
            overrideBundle = language.makeBundle()
        }
    }

    private var overrideBundle: Bundle?

    private init() {
        // Legacy cleanup: the restart-based switcher stored an
        // AppleLanguages override; it no longer applies.
        UserDefaults.standard.removeObject(forKey: "AppleLanguages")

        let stored = UserDefaults.standard.string(forKey: Self.defaultsKey) ?? ""
        let lang = AppLanguage(rawValue: stored) ?? .system
        self.language = lang
        self.overrideBundle = lang.makeBundle()
    }

    /// Look up a catalog key in the selected language. The key is the
    /// English source text, so English and unknown keys fall through
    /// naturally.
    func tr(_ key: String) -> String {
        switch language {
        case .system:
            return Bundle.main.localizedString(forKey: key, value: nil, table: nil)
        case .en:
            return key
        case .zhHans:
            return overrideBundle?.localizedString(forKey: key, value: key, table: nil) ?? key
        }
    }

    /// Format variant for keys containing %@ placeholders.
    func tr(_ key: String, _ args: CVarArg...) -> String {
        String(format: tr(key), arguments: args)
    }
}
