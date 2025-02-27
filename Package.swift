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
            url: "https://github.com/session-foundation/libsession-util/releases/download/v1.2.0/libsession-util.xcframework.zip",
            checksum: "b01d55391cb06b770b571e97c966fb87eb9c0e74b65d5c0f94853b730d1635ff"
        )
    ]
)
