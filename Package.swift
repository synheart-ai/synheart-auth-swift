// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SynheartAuth",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "SynheartAuth",
            targets: ["SynheartAuth"]
        ),
    ],
    targets: [
        .target(
            name: "SynheartAuth",
            path: "Sources/SynheartAuth"
        ),
        .testTarget(
            name: "SynheartAuthTests",
            dependencies: ["SynheartAuth"],
            path: "Tests/SynheartAuthTests"
        ),
    ]
)
