import XCTest

final class VaultUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    private func configuredApplication() -> XCUIApplication {
        let app = XCUIApplication()
        #if os(iOS)
        // appLanguage is Vault's runtime override, separate from AppleLanguages.
        app.launchArguments += [
            "-AppleLanguages", "(en)", "-AppleLocale", "en_US",
            "-appLanguage", "en", "-AppleInterfaceStyle", "Light"
        ]
        #endif
        return app
    }

    @MainActor
    private func launchApplication() -> XCUIApplication {
        let app = configuredApplication()
        app.launch()
        addTeardownBlock { @MainActor in
            if (self.testRun?.failureCount ?? 0) > 0 {
                self.attachScreenshot("Failure", app: app)
                let tree = XCTAttachment(string: app.debugDescription)
                tree.name = "Failure accessibility tree"
                tree.lifetime = .keepAlways
                self.add(tree)
            }
            app.terminate()
        }
        return app
    }

    @MainActor
    private func attachScreenshot(_ name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    @MainActor
    func testAppLaunch() throws {
        _ = launchApplication()
    }

    #if os(iOS)
    @MainActor
    private func selectTab(_ label: String, in app: XCUIApplication, ready: XCUIElement) {
        let tab = app.tabBars.buttons[label]
        XCTAssertTrue(tab.waitForExistence(timeout: 10), app.debugDescription)
        tab.tap()
        XCTAssertTrue(ready.waitForExistence(timeout: 10), app.debugDescription)
        let selected = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in tab.exists && tab.isSelected }, object: nil
        )
        XCTAssertEqual(XCTWaiter.wait(for: [selected], timeout: 10), .completed)
    }

    @MainActor
    func testStatusPage() throws {
        let app = launchApplication()
        let tab = app.tabBars.buttons["Status"]
        XCTAssertTrue(tab.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(tab.isSelected)
        let connection = app.buttons["vpn.connection"]
        XCTAssertTrue(connection.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(connection.isEnabled)
        XCTAssertFalse(connection.frame.isEmpty)
        XCTAssertEqual(connection.frame.width, 92, accuracy: 2)
        XCTAssertTrue(
            app.windows.firstMatch.frame.contains(connection.frame),
            "Connection control is outside the app window: \(connection.frame)"
        )
        XCTAssertTrue(app.staticTexts["No configuration"].exists || app.staticTexts["Disconnected"].exists)
        attachScreenshot("iOS Status", app: app)
        if app.staticTexts["No configuration"].exists {
            connection.tap()
            XCTAssertTrue(app.textFields["Profile Name"].waitForExistence(timeout: 5))
        }
    }

    @MainActor
    func testDiagnosticsAndRuntimeLogs() throws {
        let app = launchApplication()
        let start = app.buttons["diagnostics.run"]
        selectTab("Diagnostics", in: app, ready: start)
        XCTAssertEqual(start.label, "Start Direct Checks")
        let probe = app.textFields["diagnostics.probeDomains"]
        let save = app.buttons["Save"]
        XCTAssertTrue(probe.exists)
        XCTAssertTrue(save.exists)
        XCTAssertGreaterThan(save.frame.minY, probe.frame.maxY)
        let logs = app.buttons["Runtime Logs"]
        XCTAssertTrue(logs.exists)
        XCTAssertGreaterThanOrEqual(logs.frame.height, 44)
        XCTAssertGreaterThan(logs.frame.width, 100)
        XCTAssertTrue(start.isEnabled)
        start.tap()
        let outcome = app.staticTexts.matching(NSPredicate(
            format: "label IN %@",
            ["Connectivity checks passed", "Connectivity issues found", "Diagnostics incomplete"]
        )).firstMatch
        XCTAssertTrue(outcome.waitForExistence(timeout: 45), app.debugDescription)
        attachScreenshot("iOS Connection Checks", app: app)
        XCTAssertFalse(app.staticTexts["Tunnel DNS · IPv4"].exists)
        XCTAssertFalse(app.navigationBars.buttons["diagnostics.run"].exists)
        XCTAssertFalse(app.buttons["Cancel"].exists)
        XCTAssertFalse(app.buttons["Copy"].exists)

        logs.tap()
        let copy = app.buttons["Copy"]
        XCTAssertTrue(copy.waitForExistence(timeout: 10), app.debugDescription)
        let clear = app.buttons["Clear"]
        XCTAssertTrue(clear.exists)
        let tabBar = app.tabBars.firstMatch
        XCTAssertLessThanOrEqual(copy.frame.maxY, tabBar.frame.minY, app.debugDescription)
        XCTAssertLessThanOrEqual(clear.frame.maxY, tabBar.frame.minY, app.debugDescription)
        let selected = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in logs.exists && logs.isSelected }, object: nil
        )
        XCTAssertEqual(XCTWaiter.wait(for: [selected], timeout: 10), .completed)
        XCTAssertFalse(start.exists)
        XCTAssertFalse(app.switches["Auto-scroll"].exists)
        XCTAssertFalse(app.textFields["Search logs"].exists)
        XCTAssertFalse(app.buttons["Application"].exists)
        XCTAssertFalse(app.buttons["Tunnel"].exists)
        let emptyLogs = app.staticTexts["No log content found."]
        let logsLoaded = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in clear.isEnabled || emptyLogs.exists }, object: nil
        )
        XCTAssertEqual(XCTWaiter.wait(for: [logsLoaded], timeout: 10), .completed)
        if clear.isEnabled {
            clear.tap()
            let confirmation = app.alerts["Clear runtime logs?"]
            XCTAssertTrue(confirmation.waitForExistence(timeout: 10))
            XCTAssertTrue(confirmation.buttons["Clear"].exists)
            confirmation.buttons["Cancel"].tap()
            XCTAssertFalse(confirmation.exists)
            XCTAssertTrue(clear.isEnabled)
        } else {
            XCTAssertFalse(copy.isEnabled)
        }
        attachScreenshot("iOS Diagnostics Logs", app: app)
    }

    @MainActor
    func testDiagnosticsDismissesKeyboardOutsideInput() {
        let app = launchApplication()
        let probe = app.textFields["diagnostics.probeDomains"]
        let keyboard = app.keyboards.firstMatch
        selectTab("Diagnostics", in: app, ready: probe)

        probe.tap()
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5), app.debugDescription)
        app.staticTexts["Test targets"].tap()
        XCTAssertTrue(keyboard.waitForNonExistence(timeout: 5), app.debugDescription)

        probe.tap()
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5), app.debugDescription)
        app.buttons["Runtime Logs"].tap()
        XCTAssertTrue(app.buttons["Clear"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(keyboard.waitForNonExistence(timeout: 5), app.debugDescription)
    }

    @MainActor
    func testProfileEditorDismissesKeyboardOutsideInput() {
        let app = launchApplication()
        let addProfile = app.buttons["Add Profile"]
        let keyboard = app.keyboards.firstMatch
        selectTab("Configure", in: app, ready: addProfile)
        addProfile.tap()

        let name = app.textFields["Profile Name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5), app.debugDescription)
        name.tap()
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5), app.debugDescription)
        app.textFields["Host"].tap()
        XCTAssertTrue(keyboard.exists, app.debugDescription)
        app.staticTexts["Profile Details"].tap()
        XCTAssertTrue(keyboard.waitForNonExistence(timeout: 5), app.debugDescription)

        app.textFields["Port"].tap()
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5), app.debugDescription)
        app.staticTexts["Profile Details"].tap()
        XCTAssertTrue(keyboard.waitForNonExistence(timeout: 5), app.debugDescription)
    }

    @MainActor
    func testAboutPage() throws {
        let app = launchApplication()
        let description = app.staticTexts["A secure VPN client for cross-regional connectivity."]
        selectTab("About", in: app, ready: description)
        XCTAssertEqual(description.label, "A secure VPN client for cross-regional connectivity.")
        XCTAssertFalse(app.buttons["View Logs"].exists)
        XCTAssertFalse(app.buttons["Copy"].exists)
        attachScreenshot("iOS About", app: app)
    }
    #endif

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            let app = configuredApplication()
            app.launch()
            app.terminate()
        }
    }
}
