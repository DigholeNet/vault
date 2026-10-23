//
//  VaultUITests.swift
//  VaultUITests
//
//

import XCTest

final class VaultUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testAppLaunch() throws {
        let app = XCUIApplication()
        app.launch()
    }

    #if os(iOS)
    @MainActor
    func testDiagnosticsAndAboutNavigationWithoutVPN() throws {
        let app = XCUIApplication()
        app.launchArguments += ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()

        let diagnostics = app.tabBars.buttons["Diagnostics"]
        XCTAssertTrue(diagnostics.waitForExistence(timeout: 10))
        XCTAssertTrue(app.descendants(matching: .any)["vpn.connection"].isHittable)
        let status = XCTAttachment(screenshot: app.screenshot())
        status.name = "iOS Status Existing Connection Icon"
        status.lifetime = .keepAlways
        add(status)
        diagnostics.tap()
        let start = app.navigationBars.buttons["Start"]
        XCTAssertTrue(start.waitForExistence(timeout: 5))
        XCTAssertFalse(start.isEnabled)
        XCTAssertFalse(app.buttons["Cancel"].exists)
        XCTAssertFalse(app.buttons["Copy"].exists)
        app.buttons["Runtime Logs"].tap()
        XCTAssertFalse(app.switches["Auto-scroll"].exists)
        XCTAssertFalse(app.textFields["Search logs"].exists)
        XCTAssertFalse(app.buttons["All"].exists)
        XCTAssertFalse(app.buttons["Application"].exists)
        XCTAssertFalse(app.buttons["Tunnel"].exists)
        let logs = XCTAttachment(screenshot: app.screenshot())
        logs.name = "iOS Diagnostics Logs"
        logs.lifetime = .keepAlways
        add(logs)

        app.tabBars.buttons["About"].tap()
        XCTAssertTrue(app.staticTexts["VPN Client"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["View Logs"].exists)
        XCTAssertFalse(app.buttons["Copy"].exists)
        let about = XCTAttachment(screenshot: app.screenshot())
        about.name = "iOS About Existing Icon"
        about.lifetime = .keepAlways
        add(about)
    }
    #endif

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}
