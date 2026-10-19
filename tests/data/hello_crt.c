/* hello_crt.c - the CRT-linked e2e fixture.
 *
 * Compiled with the statically linked CRT (/MT): the startup runs the real
 * __scrt_common_main init walk (the SEH frame, the _initterm table walks,
 * the kernel32 imports for the init), main() formats through the static CRT
 * into a guest file, and the exit path rides ExitProcess with the main
 * return value.
 *
 * Rebuild: cl /nologo /c /O2 /MT tests\data\hello_crt.c /Fotests\data\hello_crt.obj
 *          link /nologo /SUBSYSTEM:CONSOLE tests\data\hello_crt.obj /OUT:tests\data\hello_crt.exe
 * (then delete the obj)
 */
#include <stdio.h>

int main(int argc, char* argv[]) {
    FILE* f = fopen("C:\\qltest\\crt.txt", "w");
    if (f != 0) {
        fprintf(f, "crt ok argc=%d arg1=%s\n", argc, argc > 1 ? argv[1] : "none");
        fclose(f);
    }
    return 7;
}
