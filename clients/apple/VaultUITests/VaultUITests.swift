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
        let connection = app.switches["vpn.connection"]
        XCTAssertTrue(connection.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(connection.isEnabled)
        XCTAssertEqual(connection.value as? String, "0")
        XCTAssertFalse(connection.frame.isEmpty)
        XCTAssertTrue(
            app.windows.firstMatch.frame.contains(connection.frame),
            "Connection control is outside the app window: \(connection.frame)"
        )
        XCTAssertTrue(app.staticTexts["Disconnected"].exists)
        attachScreenshot("iOS Status", app: app)
    }

    @MainActor
    func testDiagnosticsAndRuntimeLogs() throws {
        let app = launchApplication()
        let start = app.navigationBars.buttons["Start"]
        selectTab("Diagnostics", in: app, ready: start)
        XCTAssertFalse(start.isEnabled)
        XCTAssertFalse(app.buttons["Cancel"].exists)
        XCTAssertFalse(app.buttons["Copy"].exists)

        let logs = app.segmentedControls.buttons["Runtime Logs"]
        XCTAssertTrue(logs.waitForExistence(timeout: 10))
        logs.tap()
        let copy = app.buttons["Copy"]
        XCTAssertTrue(copy.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(app.buttons["Clear"].exists)
        let selected = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in logs.exists && logs.isSelected }, object: nil
        )
        XCTAssertEqual(XCTWaiter.wait(for: [selected], timeout: 10), .completed)
        XCTAssertFalse(start.exists)
        XCTAssertFalse(app.switches["Auto-scroll"].exists)
        XCTAssertFalse(app.textFields["Search logs"].exists)
        XCTAssertFalse(app.buttons["Application"].exists)
        XCTAssertFalse(app.buttons["Tunnel"].exists)
        attachScreenshot("iOS Diagnostics Logs", app: app)
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
