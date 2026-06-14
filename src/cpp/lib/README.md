# Build liboqs on Windows & Linux

This guide provides step-by-step instructions for building `liboqs` as a shared library (`.dll` and `.lib` import library) natively on Windows using the Microsoft Visual C++ (MSVC) compiler. We explicitly disable OpenSSL dependencies (`-DOQS_USE_OPENSSL=OFF`) to keep the library lightweight, isolated, and conflict-free for integration into other projects like Hybrid CP-ABE.

## Prerequisites

- **CMake** (3.14 or later)
- **Microsoft Visual Studio 2022** (with MSVC compiler v142/v143 installed)
- **Ninja** (Recommended build system, often bundled with CMake or Visual Studio)

---

## 1. Build Instructions

To build `liboqs` using MSVC, you must run the commands within the Developer Command Prompt so that the `cl.exe` compiler and linker are recognized.

1. Open the **x64 Native Tools Command Prompt for VS 2022** (You can search for this in the Windows Start Menu).
2. Navigate to the root folder of the `liboqs` source code.
3. Run the following commands:

```cmd
mkdir build_msvc
cd build_msvc
cmake -G "Ninja" -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF ..
cmake --build . --config Release
```

> **Important Note:** When compiling, the build process might fail right at the end (around 99%) with a `fatal error LNK1120: unresolved externals` while trying to link test files (like `vectors_sig.exe`). **You can safely ignore this!** The core library (`oqs.dll` and `oqs.lib`) has already been generated successfully before this test-linking phase.

---

## 2. Output Files & Integration

After the build finishes, you will find the necessary files in your `build_msvc` directory:

*   **The Shared Library (DLL):** `build_msvc\bin\oqs.dll`
    *   *Action:* Copy this file into the same directory as your final `.exe` application.
*   **The Import Library:** `build_msvc\lib\oqs.lib`
    *   *Action:* Add this file to your linker inputs in your Visual Studio project properties or CMake `target_link_libraries`.
*   **The Headers:** `build_msvc\include\oqs\`
    *   *Action:* Add this path to your compiler's Additional Include Directories so you can `#include <oqs/oqs.h>`.

---

## 3. Build Instructions for Linux (Ubuntu/WSL)

If you are deploying your project to a Linux environment or using WSL (Windows Subsystem for Linux), follow these steps to build both the shared (`.so`) and static (`.a`) libraries.

### Prerequisites

Ensure you have the required build tools installed:
```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential ninja-build
```

### Build the Shared Library (`.so`)

1. Open your Linux terminal or WSL.
2. Navigate to the root folder of the `liboqs` source code.
3. Run the following commands:
```bash
mkdir -p build_linux_shared
cd build_linux_shared
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF ..
cmake --build .
```
The shared library `liboqs.so` will be generated in `build_linux_shared/lib/` (or `build_linux_shared/bin/`).

### Build the Static Library (`.a`)

To statically link `liboqs` directly into your application:
```bash
cd ..
mkdir -p build_linux_static
cd build_linux_static
cmake -GNinja -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF ..
cmake --build .
```
The static library `liboqs.a` will be generated in `build_linux_static/lib/`.

### Integration on Linux

*   **Shared Library (`.so`):** Copy `liboqs.so` to a directory in your library path (e.g., `/usr/local/lib`) or the same folder as your executable, and compile your project with `-loqs`.
*   **Static Library (`.a`):** Link `liboqs.a` directly to your executable during compilation.
*   **Headers:** Include the `build_linux_shared/include/oqs/` (or static) directory using the `-I` flag.
