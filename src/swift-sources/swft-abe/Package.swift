// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "swft-abe",
    platforms: [
        .macOS(.v10_15),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "ClibHybridABE",  // Tên của thư viện C
            dependencies: [],
            path: "Sources/ClibHybridABE",
            linkerSettings: [
                .unsafeFlags(["-L/home/wanthinnn/Documents/swft-abe/lib/dynamic", "-lhybrid-cp-abe"])  // Đảm bảo thư viện .so có thể được tìm thấy
            ]
        ),

    ]
)
