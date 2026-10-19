/* hello_x64.c - the real-PE end-to-end fixture source.
 *
 * Compiled once on the host toolchain (x64, /NODEFAULTLIB, the imports
 * declared explicitly so the import table stays exactly on the surface the
 * port's kernel32 registry implements) and checked into the repo as
 * tests/data/hello_x64.exe. The emulator fixture loads it through the real
 * PE path: the loader maps the sections, resolves the import table through
 * the ApiRegistry (the IAT walk over the mapped kernel32 exports) and runs
 * to ExitProcess.
 *
 * Rebuild (regenerate the fixture binary) with:
 *   cl /nologo /c /O2 /GS- tests/data/hello_x64.c
 *   link /nologo /NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:main hello_x64.obj kernel32.lib
 */

typedef unsigned long DWORD;
typedef unsigned long* PDWORD;
typedef void* HANDLE;
typedef const char* LPCSTR;
typedef char* LPSTR;
typedef void* LPVOID;

#define GENERIC_WRITE 0x40000000L
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_NORMAL 0x00000080L
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) void* __stdcall GetModuleHandleA(LPCSTR lpModuleName);
__declspec(dllimport) void* __stdcall LoadLibraryA(LPCSTR lpLibFileName);
__declspec(dllimport) void* __stdcall GetProcAddress(void* hModule, LPCSTR lpProcName);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) HANDLE __stdcall CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
                                                   DWORD dwShareMode, LPVOID lpSecurityAttributes,
                                                   DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                                   HANDLE hTemplateFile);
__declspec(dllimport) int __stdcall WriteFile(HANDLE hFile, LPCSTR lpBuffer, DWORD nNumberOfBytesToWrite,
                                              PDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped);
__declspec(dllimport) int __stdcall CloseHandle(HANDLE hObject);
__declspec(dllimport) void __stdcall ExitProcess(unsigned uExitCode);

void main(void) {
    /* the loader census: the module handle, the dynamic load and the
     * export lookup - all resolved through the port's kernel32 registry */
    volatile HANDLE k32 = GetModuleHandleA("kernel32.dll");
    volatile HANDLE k32b = LoadLibraryA("kernel32.dll");
    (void)k32;
    (void)k32b;

    HANDLE out = CreateFileA("C:\\qltest\\hello.txt", GENERIC_WRITE, 0, (LPVOID)0,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, (HANDLE)0);
    const char msg[] = "hello from qiling\r\n";
    DWORD written = 0;
    WriteFile(out, msg, sizeof(msg) - 1, &written, (LPVOID)0);
    CloseHandle(out);

    ExitProcess(42);
    for (;;);
}
