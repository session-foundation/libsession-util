// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibSessionUtil",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(name: "SessionUtil", targets: ["SessionUtil"])
    ],
    targets: [
        .binaryTarget(
            name: "SessionUtil",
            url: "https://github.com/oxen-io/libsession-util/releases/download/v1.2.0-rc.1/libsession-util.xcframework.zip",
            checksum: "c3dbb5dca0556943dbed7f249e397be5d97eb09a97bdd9060644b6ff2e155199"
        )
    ]
)
