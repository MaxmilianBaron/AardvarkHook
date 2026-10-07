# AardvarkHook

C++17 function hooks for **Windows x86 and x64**. MIT licensed, with no external library dependencies.

Reversible entry patches and callable trampolines, with automatic entry capture or explicit signatures. Relocates supported calls, branches, counter loops and x64 RIP-relative operands. Trampoline placement respects operand reach and skips occupied memory regions. Batch changes preflight every target and attempt reverse-order rollback on failure. `ExecutionGate` coordinates participating callers.

Build with Visual Studio 2022 C++ tools, the Windows SDK and CMake 3.21 or newer:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Use `-A Win32` in a separate directory for x86. CI builds and installs Debug and Release libraries on both architectures.

To use it in another CMake project:

```cmake
add_subdirectory(AardvarkHook)
target_link_libraries(your_app PRIVATE AardvarkHook::AardvarkHook)
```

Lifecycle changes require quiescent execution; there is no automatic thread suspension, complete instruction decoder, x64 unwind registration or process injection.
