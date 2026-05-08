import Foundation
import os

/// Thin wrapper around `os.Logger` for internal auth logging.
struct AuthLogger {
    private let logger: Logger

    static let shared = AuthLogger()

    private init() {
        self.logger = Logger(subsystem: "ai.synheart.auth", category: "SynheartAuth")
    }

    func debug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    func warning(_ message: String) {
        logger.warning("\(message, privacy: .public)")
    }

    func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }
}
