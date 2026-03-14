# Windows API Hashing

## Overview/Introduction

This is a C++ implementation of a Windows API Hashing technique utilized in malware development to stealthily resolve Windows API functions during runtime. 

By employing a custom string hashing algorithm (like seen in ransomware like REVil), we can hide imported Windows API functions from the executable's Import Address Table (IAT). This reduces the statically analyzable footprint of the binary, therefore making it harder for traditional AV and EDR solutions to determine the program's intent through static analysis alone.

## Principle of Operation

The implementation dynamically resolves API functions entirely from memory without relying on `GetModuleHandle` or `GetProcAddress`:

1. **Locating the PEB (Process Environment Block):** Find the PEB directly via the Thread Environment Block (TEB) using the `__readfsdword(0x30)` compiler intrinsic (targeting the x86 architecture).
2. **Traversing the Loader Data:** Through the PEB, access the `PEB_LDR_DATA` structure, which contains the `InLoadOrderModuleList` doubly-linked list holding information about all loaded modules (DLLs) in the current process space.
3. **Module Resolution by Hash:** Traverse this linked list, continually taking the Base DLL name (e.g., `KERNEL32.DLL`), hashing it using the custom `REVilCustomHashModule` algorithm, and comparing it to a target hash. Once a match is found, it grabs the base address of that loaded module.
4. **Parsing PE Headers:** Using the module's base address, manually parse the DOS Header (`IMAGE_DOS_HEADER`) and NT Headers (`IMAGE_NT_HEADERS`) to locate the Data Directory, before pointing to the Export Directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`).
5. **Function Resolution by Hash:** Iterate through the `AddressOfNames` array within the Export Directory. Hash each exported function name using `REVilCustomHashFunction`. If the computed hash matches the pre-calculated target hash (something like `0x5ed17` corresponding to `LoadLibraryA`), use the matched name's index to look up the function's ordinal and retrieve the function's Virtual Address from the `AddressOfFunctions` array.
6. **Execution:** Cast the dynamically resolved address to the appropriate function pointer prototype and execute. In this POC, it dynamically resolves `LoadLibraryA` from `kernel32.dll` to load `USER32.DLL`, calculates the hash for `MessageBoxA`, resolves it dynamically, and pops a message box.

## Project File Structure

```text
WindowsAPIHashing/
├── WindowsAPIHashing/
│   ├── WindowsAPIHashing.cpp             # Main source code containing the hashing logic, PEB traversal, and PE header parsing.
│   ├── WIndowsAPIHashing.vcxproj         # Visual Studio C++ project file.
│   └── WIndowsAPIHashing.vcxproj.filters # Visual Studio project filters file.
└── WIndowsAPIHashing.sln                 # Main Visual Studio Solution file.
```

## Requirements

*   **Operating System:** Windows Environment.
*   **Architecture:** The current code utilizes the `__readfsdword(0x30)` intrinsic, which is specific to the **x86 (32-bit)** architecture. To target x64, this intrinsic needs to be updated to `__readgsqword(0x60)`.
*   **Compiler/IDE:** Developed using Microsoft Visual Studio. MSVC compiler is recommended due to the use of Windows-specific types, structs (like `PEB`, `TEB`, `LDR_MODULE`), and compiler intrinsics.