# Hybrid CP-ABE Library
Hybrid Ciphertext Policy Attribute Based Encryption Library for C/C++ in Windows/Linux

## Prerequisites

- [CryptoPP Library](https://github.com/weidai11/cryptopp)
- [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807)
- [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi)


## Building for Windows

1. Clone the repository:
    ```sh
    https://github.com/WanThinnn/Hybrid-CP-ABE-Library.git
    ```
2. Navigate to the project directory:
_Using x64 Native Tools Command Prompt for VS 2022_
   ```sh
    cd Hybrid-CP-ABE-Library/cpp-sources
    code . #for open projects Visual Studio Code
    ```
4. Configure `tasks.json` to build the project using `cl.exe`:
    - Create or open the `.vscode` folder in your project directory.
    - Create a `tasks.json` file inside the `.vscode` folder with the following content:

  ```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "shell",
            "label": "C/C++: cl.exe build executable",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/Fe:${fileDirname}\\${fileBasenameNoExtension}.exe",
                "${file}",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib",
                "cryptlib.lib",
                "bcrypt.lib",
                "advapi32.lib",
                "ntdll.lib",
                "Ws2_32.lib",
                "/MACHINE:X64"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": "build",
            "detail": "Task to build executable."
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build executable for hybrid CP-ABE",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/Fe:${fileDirname}\\${fileBasenameNoExtension}.exe",
                "${file}",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "libac17_gcm256.lib",
                "/MACHINE:X64"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": "build",
            "detail": "Task to build executable for hybrid CP-ABE."
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build static library for hybrid CP-ABE",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/c",
                "${file}",
                "/I${workspaceFolder}\\include"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "Task to build static library for hybrid CP-ABE."
        },
        {
            "type": "shell",
            "label": "C/C++: lib.exe create static library for hybrid CP-ABE",
            "command": "lib.exe",
            "args": [
                "/OUT:${fileDirname}\\${fileBasenameNoExtension}.lib",
                "${fileDirname}\\${fileBasenameNoExtension}.obj",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib",
                "cryptlib.lib",
                "bcrypt.lib",
                "advapi32.lib",
                "ntdll.lib"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "Task to create static library."
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build dynamic linking library (DLL) for hybrid CP-ABE",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/LD",
                "/DBUILD_DLL",
                "/Fe:${fileDirname}\\${fileBasenameNoExtension}.dll",
                "${file}",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib",
                "cryptlib.lib",
                "bcrypt.lib",
                "advapi32.lib",
                "ntdll.lib",
                "/MACHINE:X64"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "C/C++: cl.exe build dynamic linking library (DLL) for hybrid CP-ABE"
        },
       
    ]
}
```

4. Build the project:
    - Open Visual Studio Code and open your project.
    - Press `Ctrl+Shift+B` to run the configured build task.
    - If everything is configured correctly, your program will be compiled using `cl.exe`.


## Building for Linux (Ubuntu 22.04)
1. Clone the repository:
    ```sh
    https://github.com/WanThinnn/Hybrid-CP-ABE-Library.git
    ```
2. Navigate to the project directory:
    ```sh
    cd Hybrid-CP-ABE-Library/cpp-sources
    code . #for open projects Visual Studio Code
    ```
3. Configure `tasks.json` to build the project using `g++`:
    - Create or open the `.vscode` folder in your project directory.
    - Create a `tasks.json` file inside the `.vscode` folder with the following content:
 ```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "shell",
            "label": "Build executable (cryptopp/rabe_ffi)",
            "command": "g++",
            "args": [
                "-O3",
                "-g2",
                "-Wall",
                "-I${workspaceFolder}/include",
                "${file}",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}",
                "-L${workspaceFolder}/lib/static-lib",
                "-lcryptopp",
                "-lrabe_ffi"
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Build executable linking cryptopp and rabe_ffi."
        },
        {
            "type": "shell",
            "label": "Build executable (hybrid CP-ABE)",
            "command": "g++",
            "args": [
                "-O2",
                "-g",
                "-Wall",
                "-I${workspaceFolder}/include",
                "${file}",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}",
                "-L${workspaceFolder}/lib/static-lib",
                "-lhybrid-cp-abe"
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Build executable linking fat library libhybrid-cp-abe.a."
        },
        {
            "type": "shell",
            "label": "Compile source for hybrid CP-ABE (1/3)",
            "command": "g++",
            "args": [
                "-O2",
                "-g",
                "-Wall",
                "-c",
                "${file}",
                "-I${workspaceFolder}/include",
                "-fPIC",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}.o"
            ],
            "problemMatcher": ["$gcc"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Compile source into object file."
        },
        {
            "type": "shell",
            "label": "Extract dependency objects (2/3)",
            "command": "bash",
            "args": [
                "-c",
                "rm -rf \"${workspaceFolder}/tmp_extracted\" && mkdir -p \"${workspaceFolder}/tmp_extracted\" && cd \"${workspaceFolder}/lib/static-lib\" && ar x libcryptopp.a && ar x librabe_ffi.a && mv *.o \"${workspaceFolder}/tmp_extracted/\""
            ],
            "problemMatcher": [],
            "group": "build",
            "detail": "Extract .o files from libcryptopp.a and librabe_ffi.a."
        },
        {
            "type": "shell",
            "label": "Create fat static library for hybrid CP-ABE (3/3)",
            "command": "bash",
            "args": [
                "-c",
                "ar rcs \"${workspaceFolder}/lib/static-lib/libhybrid-cp-abe.a\" \"${fileDirname}/${fileBasenameNoExtension}.o\" \"${workspaceFolder}/tmp_extracted/\"*.o && rm -rf \"${workspaceFolder}/tmp_extracted\""
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Combine object files into libhybrid-cp-abe.a."
        },
        {
            "type": "shell",
            "label": "Build shared library for hybrid CP-ABE",
            "command": "g++",
            "args": [
                "-O2",
                "-g",
                "-Wall",
                "-fPIC",
                "-DBUILD_DLL",
                "-I${workspaceFolder}/include",
                "${file}",
                "-shared",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}.so",
                "-L${workspaceFolder}/lib/static-lib",
                "-lhybrid-cp-abe",
                "-lcryptopp",
                "-lrabe_ffi"
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Build shared library (.so) for hybrid CP-ABE."
        }
    ]
}

```
4. Build the project:
    - Open Visual Studio Code and open your project.
    - Press `Ctrl+Shift+B` to run the configured build task.
    - If everything is configured correctly, your program will be compiled using `g++`.
## Usage

### Using the Executable

To use the pre-built executable, navigate to the `CPABE-AC17-Scheme/demo` directory and run the `ac17_cli_app.exe` file:

```sh
cd Hybrid-CP-ABE-Library/demo
./hybrid-cp-abe.exe
```


The usage of the executable is as follows:
```sh
Usage: hybrid-cp-abe.exe [setup|genkey|encrypt|decrypt]
Usage: hybrid-cp-abe.exe setup <path_to_save_file>
Usage: hybrid-cp-abe.exe genkey <public_key_file> <master_key_file> <attributes> <private_key_file>
Usage: hybrid-cp-abe.exe encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>
Usage: hybrid-cp-abe.exe decrypt <public_key_file> <private_key_file> <ciphertext_file> <recovertext_file>
```

Example commands:
```sh
./hybrid-cp-abe.exe setup "test_case" Base64
./hybrid-cp-abe.exe genkey "test_case/public_key.key" "test_case/master_key.key" "A B C" "test_case/private_key.key"
./hybrid-cp-abe.exe encrypt "test_case/public_key.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
./hybrid-cp-abe.exe decrypt "test_case/public_key.key" "test_case/private_key.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```
### Integrating the Library
After building the library, you can integrate it into any program on Windows/Linux. Here are the steps to include the library in your project.
Please go to <b>python-sources</b> folder to see more.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for the [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi) project and the [CryptoPP](https://github.com/weidai11/cryptopp) Library for helping me build this library.
## License

This project is open-source and available for anyone to use, modify, and distribute. We encourage you to clone, fork, and contribute to this project to help improve and expand its capabilities.
By contributing to this project, you agree that your contributions will be available under the same open terms.
