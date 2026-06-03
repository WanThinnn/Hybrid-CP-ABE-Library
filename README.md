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
    cd Hybrid-CP-ABE-Library/src/cpp
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
            "label": "Build Hybrid CP-ABE CLI Executable",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/Fe:${workspaceFolder}\\hybrid-cp-abe.exe",
                "${workspaceFolder}\\hybrid-cp-abe.cpp",
                "${workspaceFolder}\\main.cpp",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static",
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
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Build CLI executable from hybrid-cp-abe.cpp + main.cpp"
        },
        {
            "type": "shell",
            "label": "Build Hybrid CP-ABE Static Library (.lib)",
            "command": "cmd",
            "args": [
                "/c",
                "cl.exe /MD /GS /O2 /Zi /EHsc /c ${workspaceFolder}\\hybrid-cp-abe.cpp /I${workspaceFolder}\\include /Fo:${workspaceFolder}\\hybrid-cp-abe.obj && lib.exe /OUT:${workspaceFolder}\\libhybrid-cp-abe.lib ${workspaceFolder}\\hybrid-cp-abe.obj /LIBPATH:${workspaceFolder}\\lib\\static librabe_ffi.lib cryptlib.lib bcrypt.lib advapi32.lib ntdll.lib"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": "build",
            "detail": "Build static library from hybrid-cp-abe.cpp only (no main.cpp)"
        },
        {
            "type": "shell",
            "label": "Build Hybrid CP-ABE DLL",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/LD",
                "/DBUILD_DLL",
                "/Fe:${workspaceFolder}\\hybrid-cp-abe.dll",
                "${workspaceFolder}\\hybrid-cp-abe.cpp",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static",
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
            "group": "build",
            "detail": "Build DLL from hybrid-cp-abe.cpp only (no main.cpp)"
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build single file executable",
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
                "/LIBPATH:${workspaceFolder}\\lib\\static",
                "librabe_ffi.lib",
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
            "detail": "Build single file as executable (for testing)"
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build executable for hybrid CP-ABE (legacy)",
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
                "/LIBPATH:${workspaceFolder}\\lib\\static",
                "libac17_gcm256.lib",
                "/MACHINE:X64"
            ],
            "problemMatcher": [
                "$msCompile"
            ],
            "group": "build",
            "detail": "Task to build executable for hybrid CP-ABE (legacy)."
        },
        {
            "type": "shell",
            "label": "Clean build artifacts",
            "command": "cmd",
            "args": [
                "/c",
                "del /Q ${workspaceFolder}\\*.obj ${workspaceFolder}\\*.exe ${workspaceFolder}\\*.dll ${workspaceFolder}\\*.lib ${workspaceFolder}\\*.pdb ${workspaceFolder}\\*.ilk ${workspaceFolder}\\*.exp 2>nul || echo Clean complete"
            ],
            "problemMatcher": [],
            "group": "build",
            "detail": "Remove build artifacts (.obj, .exe, .dll, .lib, .pdb)"
        }
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
    cd Hybrid-CP-ABE-Library/src/cpp
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
            "label": "1. Build executable (.exe)",
            "command": "g++",
            "args": [
                "-O2", "-g", "-Wall",
                "-I${workspaceFolder}/include",
                "${file}",
                "-o", "${fileDirname}/${fileBasenameNoExtension}",
                "-L${workspaceFolder}/lib/static",
                "-lhybrid-cp-abe"
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Compile currently open file and link with libhybrid-cp-abe.a"
        },
        {
            "type": "shell",
            "label": "2. Build shared library (.so)",
            "command": "g++",
            "args": [
                "-O2", "-g", "-Wall", "-fPIC", "-DBUILD_DLL",
                "-I${workspaceFolder}/include",
                "${workspaceFolder}/hybrid-cp-abe.cpp",
                "-shared",
                "-o", "${workspaceFolder}/lib/dynamic/libhybrid-cp-abe.so",
                "${workspaceFolder}/lib/static/libcryptopp.a",
                "${workspaceFolder}/lib/static/librabe_ffi.a"
            ],
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Build shared library (libhybrid-cp-abe.so)"
        },
        {
            "type": "shell",
            "label": "3. Build static library (.a)",
            "command": "bash",
            "args": [
                "-c",
                "echo 'Compiling...' && g++ -O2 -g -Wall -c \"${workspaceFolder}/hybrid-cp-abe.cpp\" -I\"${workspaceFolder}/include\" -fPIC -o \"${workspaceFolder}/hybrid-cp-abe.o\" && echo 'Extracting dependencies...' && rm -rf \"${workspaceFolder}/tmp_extracted\" && mkdir -p \"${workspaceFolder}/tmp_extracted\" && cd \"${workspaceFolder}/lib/static\" && ar x libcryptopp.a && ar x librabe_ffi.a && mv *.o \"${workspaceFolder}/tmp_extracted/\" && echo 'Archiving...' && ar rcs \"${workspaceFolder}/lib/static/libhybrid-cp-abe.a\" \"${workspaceFolder}/hybrid-cp-abe.o\" \"${workspaceFolder}/tmp_extracted/\"*.o && echo 'Cleaning up...' && rm -rf \"${workspaceFolder}/tmp_extracted\" \"${workspaceFolder}/hybrid-cp-abe.o\" && echo 'Done! Output at lib/static/libhybrid-cp-abe.a'"
            ],
            "problemMatcher": [],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Build static library (libhybrid-cp-abe.a) and clean up temporary .o files"
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



The usage of the executable is as follows:
```sh
Usage: hybrid-cp-abe.exe [setup|genkey|encrypt|decrypt]
Usage: hybrid-cp-abe.exe setup <path_to_save_file>
Usage: hybrid-cp-abe.exe genkey <master_key_file> <attributes> <private_key_file>
Usage: hybrid-cp-abe.exe encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>
Usage: hybrid-cp-abe.exe decrypt <private_key_file> <ciphertext_file> <recovertext_file>
```

Example commands:
```sh
hybrid-cp-abe.exe setup test_case
hybrid-cp-abe.exe genkey "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
hybrid-cp-abe.exe encrypt "test_case/cpabe_pk.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
hybrid-cp-abe.exe decrypt "test_case/cpabe_sk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```
### Integrating the Library
After building the library, you can integrate it into any program on Windows/Linux. Here are the steps to include the library in your project.
Please go to <b>python-sources</b> folder to see more.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for the [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi) project and the [CryptoPP](https://github.com/weidai11/cryptopp) Library for helping me build this library.
## License

This project is open-source and available for anyone to use, modify, and distribute. We encourage you to clone, fork, and contribute to this project to help improve and expand its capabilities.
By contributing to this project, you agree that your contributions will be available under the same open terms.
